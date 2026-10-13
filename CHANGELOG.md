# Changelog

## [Unreleased]

This release reworks ThreatCode around one idea: show how an attacker gets from the internet to your data.
It builds one graph from everything it is given, finds attack paths over directed reachability edges, and joins the results of the scanners you already run instead of competing with them.
The CLI has two commands, the exit codes mean something stricter, and the LLM is opt-in.
[Migrating from 0.9](docs/migrating.md) lists what to change.

Before the first release of this line is published, work through [docs/releasing.md](docs/releasing.md).
Until the package is live on PyPI (`curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/threatcode/json` must print 200), install with `pip install "git+https://github.com/ajokunu/ThreatCode.git"`.

### Added

#### One entry point, and a pipeline that does not fail silently

- **`threatcode scan PATH...` reads files, directories and standard input** into one graph.
  `-` reads standard input and `--stdin-name` names it (`main.tf`, `Dockerfile`, `plan.json`); without a name, input that starts with `{` or `[` is JSON and anything else is YAML.
- **A directory is understood the way the tools that wrote it understand it.**
  `.tf`, `.tofu` and `.tf.json` files are one Terraform module, and a plan JSON in the same directory replaces the module.
  Every `Chart.yaml` is one Helm chart that owns its `templates/` and `charts/`, so templates are never scanned as raw manifests.
  Any other supported file is its own unit, and addresses that two units share are prefixed with the unit path (`infra/net::aws_vpc.main`) in the same order on every run.
- **A walker for repositories you did not write.**
  It reads only regular files, skips and counts symlinks inside the tree (a symlink you name is followed), skips and counts pipes, sockets and devices, and does not enter `.git`, `node_modules`, `.terraform`, `vendor`, virtualenvs, build output, caches and every dot-directory except `.cursor` and `.vscode`.
  A JSON or YAML file over 50 MB is set aside as not infrastructure.
- **Exit codes 0, 1 and 2, where 2 means the scan could not be trusted.**
  Exit 2 covers an unreadable path, a file a parser claimed but could not parse, a scan with nothing to model, an ingest file that is unreadable or unrecognized, a bad option, and `--strict` with any coverage gap.
  Exit 1 means a finding or attack path at or above `--fail-on` survived suppressions and the baseline, and 2 wins over 1 wins over 0.
  Findings from the LLM are advisory and never set exit 1.
- **`--fail-on` gates on the effective severity, and `--min-severity` only changes what you see.**
  `--fail-on` takes `critical`, `high`, `medium`, `low`, `info` or `none`.
- **A `coverage` block in every report** lists the files discovered, the units parsed, the files that are not infrastructure, symlinks and special files skipped, input errors, coverage gaps, failed rule evaluations and the suppressed and baselined counts.
  Gaps are the warnings parsers and the graph record: an unanalysed module call, a Helm fallback render, values known only after apply, an unresolved CloudFormation intrinsic, a skipped document.
  Errors and gaps always reach stderr, even with `-q`, and `--strict` turns any gap into exit 2.
- **Fingerprints, suppressions and baselines.**
  Every finding has a 16 character fingerprint built from the kind of finding, its rule, its resource address and its root-relative file, never from property values.
  `.threatcodeignore` entries are `<ID> [resource=GLOB] [file=GLOB] [exp:YYYY-MM-DD] [reason="text"]`, where `ID` is a rule id, a finding id, a fingerprint, an attack path id or a CVE or GHSA alias.
  An entry without a reason, a global entry without an end date, an entry that names a removed rule and an entry that expired are warned, and a notice in CI explains that a pull request can edit an ignore file inside the scanned tree.
  `--write-baseline FILE` records every finding and attack path, and `--baseline FILE` hides those findings and attack paths from the gate and the listings, so a new path still fails the gate; a baseline is not written when the scan had input errors.
  A baseline written by an older version lists no attack path and hides none.
- **Reproducible output.**
  `SOURCE_DATE_EPOCH` fixes the timestamp and `--no-timestamp` leaves it out.
  Findings are sorted, and every path in a report is POSIX and relative to the scan root, so the same tree gives byte-identical output wherever it is checked out.
- **One settings resolver.**
  A flag wins over `THREATCODE_FAIL_ON`, `THREATCODE_MIN_SEVERITY`, `THREATCODE_FORMAT` and `THREATCODE_LLM`, which win over the config file, which wins over the default.
  Config models reject unknown keys with a suggestion, and graph limits can be set with `--max-nodes`, `--max-edges`, `max_nodes`, `max_edges` and the `THREATCODE_MAX_*` variables.
- **A config file inside the scanned repository cannot widen its own trust.**
  An auto-discovered `.threatcode.yml` is announced on stderr and only `min_severity` and `format` are read from it.
  `fail_on`, `rules`, `llm`, `redaction` and the graph limits come only from a file named with `--config`.
- **A text report for terminals** with a verdict line, the attack paths, a table that fits the terminal width, and the coverage block.
  Group options `-v`, `-q`, `--debug`, `--no-color` and `--version` go before the command, and every help text ends with examples and the exit codes.
- **`diff` checks what it is given and lists attack paths first.**
  Both files must be `threatcode scan -f json` reports, attack paths that appeared or closed are compared by id, `-f text` and `-o` are supported, and `--fail-on-new SEVERITY` also fails on a new attack path.
- **A Python API through the same pipeline:** `scan(paths, **settings)` returns the report dict, `analyze(paths, **settings)` the graph with the report, and `run_scan(ScanRequest)` the exit code and the coverage.
  Names load on first use, so `import threatcode` stays cheap.
- **`-q`, `-v` and `--no-color` work after the command.**
  `threatcode scan infra/ -q` used to fail with `No such option: -q`.
  Both `scan` and `diff` accept the three options, they add to the same options given before the command, and each command's help lists them.
  `--debug` stays a group option.
- **`-o -` and `-o /dev/stdout` write the report to standard output** and print no `Report written to` line, where `-o -` used to create a file named `-`.
- **The format follows the `-o` extension when `-f` is absent.**
  `-o results.sarif` writes SARIF, `-o report.md` Markdown, `-o flow.mmd` Mermaid, `-o map.svg` the diagram and `-o out.json` the JSON report; a name no format claims still writes JSON.
  `-f json -o results.sarif` still writes JSON and says on stderr that the file name suggests SARIF (the warning survives `-q`).
  A format set by `THREATCODE_FORMAT` or the config counts as given.
- **`--source-root DIR`** sets the repository root that SARIF and Bitbucket paths are relative to, for a checkout with no `.git` directory.
- **`--diagram-max-rows N`, `--diagram-expand-docker` and `--diagram-detail auto|full|collapsed`** reach the SVG diagram.
  Giving one with another format is a usage error instead of being ignored.
- **The removed 0.9 commands `fs`, `repo`, `image`, `vuln`, `db`, `secret`, `sbom` and `license` answer with what replaces them** and a pointer to `docs/migrating.md` (exit 2), instead of `No such command`.
  They stay out of `--help`.
- **`threatcode scan --include-graph`** adds the graph (nodes and edges, no properties) to the JSON report.
- **Formatter helpers:** `threatcode.formatters.RepoPaths`, `find_repo_root`, `format_for_extension`, `extension_mismatch`, `deprecation_notice` and `visible_format_names`, and the `repo_root` and `fail_on` fields of `RenderOptions`, which `format_sarif` and `format_bitbucket` also take as arguments.

#### Attack paths

- **Attack paths are an engine result** (`report.attack_paths`, the `attack_paths` key of the JSON report, and the gate).
  A path is a chain of resources an attacker can follow over directed reachability edges, from a synthetic `internet` node to a crown jewel: a data store, a secret store, an identity that may do everything, a Kubernetes Secret or cluster-admin grant, or an MCP server that reads private data.
  It ends at the first crown jewel it reaches, runs through at most 8 edges and visits no node twice.
- **Each hop says what enables it.**
  `enabled_by` lists the rule, secret and scanner findings on the hop, `via` names the edge to the next hop (the security group whose rule admits the traffic, the listener, the role binding, with protocol and ports), and `techniques` gives the ATT&CK technique of the step.
  A path is kept only when some finding enables a hop or the target.
- **Severity, score and order.**
  The severity is the worst effective severity of the enabling findings, one level higher when the target is a tagged data store, and never above `high` unless every edge is definite.
  Paths are ordered by score, routes that differ only by the instance of a counted resource are one path with `alternatives`, and at most 5 routes per target and 100 paths are kept.
- **A reachability layer** adds directed `network_flow`, `data_flow` and `iam_binding` edges from facts the input states.
  AWS: security group rules between groups and from the internet, load balancer listeners and target groups, CloudFront origins, API Gateway integrations, Lambda permissions and function URLs, public buckets, public EKS endpoints, Auto Scaling groups, ECS services, instance profiles, trust policies, attached and inline policies and resource policies.
  Kubernetes: Ingress to Service to workload, the Secrets a workload reads, its ServiceAccount, and the Roles a binding grants, across files.
  MCP: servers that ingest untrusted content or are remote are entered from the internet, and content flows through the agent to the servers that read private data.
- **Exposure on every node** (`internet`, `internal` or `unknown`), decided from the signals the configuration states, with documented provider defaults for HCL and CloudFormation input only.
  A flag counts as true only when it is true: `(known after apply)`, a variable and the string `"false"` do not.
- **Contextual severity.**
  A finding keeps its base severity and gains `effective_severity` and `severity_reason`: one level up for a weakness on a resource the internet reaches, one level up on a data store tagged with a sensitive classification, one level down for exposure tagged as intentional (`Public=true`, `Intent=public`, `threatcode:intent=public`).
- **Boundary threats come from traffic.**
  One finding per pair of resources whose traffic crosses a trust zone, with protocol, ports and whether authentication and encryption are declared, and a STRIDE category, ATT&CK techniques and severity that follow the flow.
- **Azure and GCP resources are not modeled for reachability.**
  They get rule findings but no exposure, edges or attack paths, and the documentation says so.
- **New categories `secret` and `api`**, many more categorized resource types for AWS, Azure and GCP, and `InfraGraph.to_export_dict()`, `subgraph()` and `reachability_subgraph()`.

#### Scanner results

- **`--ingest` joins the results of the scanners you already run** (Trivy JSON, Grype JSON, OSV-Scanner JSON and SARIF 2.1.0 from Checkov, Gitleaks, Trivy config and others), repeatable, detected from the content.
  A finding is placed by the first key that matches: the container image reference a workload holds (Kubernetes, ECS, Lambda, `user_data`, Dockerfile stages), the file and line of a resource, or the directory of a lockfile.
  A finding no key places is kept and counted as a coverage gap, severities map the same way for every tool, the same advisory from two tools is one finding, and secrets in a result are never copied.

#### Parsers

- **Terraform source is read the way Terraform reads it.**
  A directory is one module with references between its files; variables take their value from `terraform.tfvars`, `*.auto.tfvars`, then defaults, then module inputs; locals, interpolation, arithmetic, conditionals and a few pure functions are evaluated without running anything; `dynamic` blocks over known collections are expanded; local modules are followed up to 8 levels; `data` blocks are context nodes; and policies have one canonical JSON form.
  A value that cannot be resolved is `values.Unknown`, never absent and never text.
  A remote module is reported as a coverage gap, and a root that only calls remote modules exits 2 instead of passing.
  python-hcl2 4.3 and 8.x are both supported.
- **Terraform plans keep their relationships** through `count`, `for_each` and modules, follow references in nested blocks, scope references to their module, resolve module inputs and outputs, mark values known only after apply as unknown, and record source lines.
- **CloudFormation properties are translated to the names the rules read** (67 resource types), a complete table maps 142 CloudFormation types to Terraform types, intrinsics are resolved where the template decides them and unknown where it does not, `Ref`, `Fn::GetAtt` and `Fn::Sub` become edges, and nothing the parser cannot model is dropped silently.
  AWS SAM templates are expanded, short-form intrinsics (`!Ref`, `!Sub`) parse, and `python scripts/gen_cfn_type_coverage.py --check` keeps rule types and the type table in step.
- **Every Kubernetes workload kind is read into one property shape** (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob) with effective security settings, per-container findings and probes and limits.
  Manifests now have edges (Ingress to Service to workload, Secrets, ConfigMaps, ServiceAccounts, bindings, NetworkPolicies), `List` documents and `kubectl -o json` are read, and resources carry file and line.
- **A real Helm renderer for when `helm` is not installed**, with every fallback reported as a coverage gap; `THREATCODE_HELM` is `auto`, `off` or `required`.
- **Dockerfiles are read the way BuildKit reads them:** case-insensitive instructions, comments inside continuations, heredocs, `# escape=`, physical line numbers, a stage model with the image summary taken from the final stage, `ONBUILD`, `EXPOSE` ranges and unknown values for tags taken from variables.
- **MCP configs resolve the effective launch command** (`cmd /c`, `bash -c`, `env`, `sudo`, `npx`, `uvx`, `docker run` and more), treat `mcp-remote`, `supergateway` and `mcp-proxy` bridges as remote servers, score secrets without storing them, normalize filesystem and container exposure, and model an agent node with the capabilities of its servers.
  Project-scoped servers in `~/.claude.json` are addressed with a hash of the project path, disabled servers keep their node, and Gemini CLI `settings.json` is read.
- **Parsers report what they skipped** as diagnostics from a closed registry, a parser can state its own edges and source lines, and a file a parser claims but cannot parse is an input error.
- **Input is decoded once:** a byte order mark is honored, invalid bytes and empty files give one message that names the file, and error messages drop exception class names.
- **Input recognition is wider and stricter.**
  A directory of `.tf`, `.tofu` and `.tf.json` files is one module, `.template`, `.cfn` and `.json` Kubernetes manifests are accepted, `Containerfile` and `Dockerfile-*` are Dockerfiles, a CloudFormation template no longer needs `AWSTemplateFormatVersion`, and `-h` works as a help flag.
  A Terraform plan needs `format_version` together with `planned_values` or `resource_changes`.
- **Parser authors** get `ParserPriority`, a `ParseFileParser` protocol for parsers that read source text, a duplicate-name check in `register_parser`, and the `ParsedResource` fields `references`, `start_line`, `end_line`, `mode` and `meta`.
  `parsers/image_ref.py` parses image references for the Dockerfile, Kubernetes and MCP parsers and for scanner-result ingestion.

#### Rules and the rule engine

- **Three-valued rule evaluation.**
  Every check ends as true, false or unknown, a rule fires only on true, and an unresolved value never produces a finding and never counts as a pass.
  On a node whose evidence is a design, a missing property is unknown instead of absent.
- **New operators:** `equals_ci`, `any_item`, `all_items`, `none_items` (quantifiers over lists of objects), `is_world_cidr` and `port_overlaps`.
  Property paths understand `a[0].b`, `a[*].b`, dots in keys (`labels.pod-security.kubernetes.io/enforce`), `labels['a.b']` and escapes.
- **Rule files are checked completely when they load** (unknown operator with a suggestion, mixed logical and property keys, wrong argument types, malformed paths, nesting deeper than 10, duplicate YAML keys), `resource_type` and `resource_types` accept a trailing `*` glob and the groups `@kubernetes_pod_workloads`, `@kubernetes_long_running` and `@kubernetes_controllers`, and rules declare a `confidence` and a `root_cause`.
- **An enrichment layer** folds companion resources into their parent and computes facts under `derived.*` (security group ingress and egress, S3 versioning, logging, encryption and public access, flow logs, diagnostic settings, WAF facts, role permissions, parsed policy statements), with `Unknown` where a link cannot be resolved and provider `DEFAULTS` for HCL and CloudFormation.
- **Every rule has a calibrated severity.**
  Absence rules stop at medium, heuristic rules at high, and critical is reserved for definitive, direct exposure of data or control; missing logging controls are STRIDE repudiation and claim no ATT&CK technique; tactics are derived from the techniques.
- **A rule that raises** is recorded in `coverage.rule_errors` and logged once instead of aborting the scan.

#### New rules

57 rules were added.
`EC2_IMDSV1`, `SG_WEB_PORT_OPEN_TO_WORLD`, `SG_TEMPORARY_OPEN`, `EKS_PUBLIC_ACCESS_ANY_CIDR`, `LAMBDA_URL_NO_AUTH`, `APIGW_METHOD_NO_AUTH`, `APIGW_ROUTE_NO_AUTH`, `APIGW_PUBLIC_POLICY`, `APIGW_NO_ACCESS_LOGS`, `ECR_MUTABLE_TAGS`, `ECR_NO_SCAN_ON_PUSH`, `ECR_PUBLIC_POLICY`, `SAGEMAKER_NOTEBOOK_DIRECT_INTERNET`, `SAGEMAKER_NOTEBOOK_ROOT_ACCESS`, `SAGEMAKER_NOTEBOOK_NO_KMS`, `S3_PUBLIC_ACCESS_BLOCK_DISABLED`, `IAM_SERVICE_WILDCARD`, `IAM_PASSROLE_WILDCARD`, `IAM_ADMIN_POLICY_ATTACHED`, `RDS_NO_DELETION_PROTECTION`, `RDS_NO_IAM_AUTH`, `REDSHIFT_PUBLIC_ACCESS`, `REDSHIFT_NO_ENCRYPTION` and `REDSHIFT_NO_LOGGING` on AWS.
`ACR_ADMIN_ENABLED`, `ACR_PUBLIC_NETWORK_ACCESS`, `ACR_ANONYMOUS_PULL`, `REDIS_NON_SSL_PORT`, `REDIS_OLD_TLS`, `REDIS_PUBLIC_NETWORK_ACCESS`, `AZURE_NSG_DATABASE_PORT_OPEN`, `AZURE_NSG_WEB_PORT_OPEN`, `AZURE_STORAGE_CONTAINER_PUBLIC` and `KEYVAULT_SHORT_SOFT_DELETE_RETENTION` on Azure.
`GCFUNC_PUBLIC_INVOKER`, `GCP_IAM_PUBLIC_MEMBER`, `GCP_IAM_SA_TOKEN_CREATOR`, `GKE_NO_MASTER_AUTHORIZED_NETWORKS`, `GKE_MASTER_WORLD_ACCESS`, `GKE_NO_WORKLOAD_IDENTITY`, `GKE_NO_SHIELDED_NODES` and `GKE_NODE_DEFAULT_SA` on GCP.
`K8S_HOST_IPC`, `K8S_SERVICE_EXPOSES_ADMIN_PORT`, `K8S_ROLE_WILDCARD_VERBS`, `K8S_ROLE_WILDCARD_RESOURCES`, `K8S_ROLE_WILDCARD_API_GROUPS`, `K8S_WILDCARD_RBAC_API_GROUPS`, `K8S_RBAC_ESCALATION_VERBS`, `K8S_RBAC_SECRETS_READ`, `K8S_RBAC_POD_EXEC`, `K8S_ANONYMOUS_PRIVILEGED_BINDING`, `K8S_ANONYMOUS_BINDING` and `K8S_ROLE_BINDING_ADMIN` on Kubernetes.
`MCP_LETHAL_TRIFECTA`, `MCP_SENSITIVE_PATHS` and `MCP_SECRET_LIKELY_IN_CONFIG` on MCP.
Four Docker rules that could never fire were revived on the properties the new parser emits: `DOCKER_NO_DIGEST_PIN`, `DOCKER_NON_MINIMAL_BASE`, `DOCKER_ADD_FROM_URL` and `DOCKER_APT_NO_CLEAN`.

#### The optional model review

- **`--dry-run` shows the real request:** the exact system prompt and user message, after pseudonymization and redaction, go to stderr or to `--dry-run-output FILE`, with the sizes and a token estimate, and no connection is opened.
- **New `llm` keys:** `api_key_env`, `timeout`, `max_retries`, `max_input_tokens` and `allow_local_network` for the Anthropic provider; `temperature` is optional.
  The `report.llm` block gains `redaction`, `context`, `prompt_hash`, `input_tokens_estimate`, `parsed_count`, `skipped_items`, `unattributed_count` and `unattributed`.
- **The OpenAI-compatible client** takes its key from `llm.api_key` or the variable named by `llm.api_key_env` (default `OPENAI_API_KEY` for `openai`), sends no `Authorization` header without a key, and retries 429 and 5xx with backoff.
- **A request is never cut:** the infrastructure context is summarized first, then resources without findings lose their properties, then low-value resources are dropped with their edges, and what was dropped is counted in the report.

#### Secrets

- **Secrets are placed on the resource that holds them.**
  The detectors run over the text of every modeled file (Terraform, `*.tfvars`, plan JSON, CloudFormation, Kubernetes manifests with base64 `Secret` data decoded, Helm values and templates) and each finding joins the graph and the attack paths.
- **New detectors:** URL userinfo, `Authorization` headers, .NET and ODBC connection strings, PKCS#8 keys, more GitHub, AWS, Google, Anthropic, OpenAI, Hugging Face and Slack token formats, Azure storage keys and `.npmrc` tokens, plus an optional high-entropy fallback.
  There are 34 detectors in all.

#### Formats and integrations

- **SARIF that GitHub code scanning can place, remember and rank:** results point at the file and region of the resource, carry `partialFingerprints`, use stable rule ids with a `security-severity`, report `executionSuccessful` and notifications for errors, gaps and a failed LLM step, and include one result per attack path with code flows.
- **Markdown written to be posted as a pull request comment:** a hidden `<!-- threatcode-report -->` marker, a verdict line, the attack paths with a Mermaid flowchart, findings in STRIDE order, a coverage section, and a cap under GitHub's comment limit.
  Text from the scanned input cannot inject Markdown.
- **A `mermaid` output format** that draws the resources an attacker can act through, with each trust zone as a subgraph and attack paths in thick red edges.
- **ATT&CK Navigator layers that load:** one entry per technique and tactic, no platform filter, a full Navigator version, revoked ids mapped to their replacement and unknown ids kept with a warning.
- **Bitbucket annotations on real files**, sorted by severity, capped at 1000 with `annotation_batches` of at most 100.
- **The SVG diagram draws the engine's attack paths,** shows containment as nested frames, collapses large graphs, wraps table cells, and is accessible (`role="img"`, title and description).
- **The GitHub Action** has `fail-on`, `ingest`, `baseline`, `comment`, `upload`, `version` and `github-token` inputs, can fail a build, installs the code at the ref it was called with, uploads SARIF, posts one sticky pull request comment, and exposes `exit-code`, `threat-count`, `path-count`, `report-file` and `sarif-file`.
  A pre-commit hook runs `threatcode scan . --fail-on high`, and Dependabot keeps the pinned actions current.
- **ATT&CK data is generated** from the official v19.2 STIX bundle (`scripts/gen_mitre_db.py`): all 858 enterprise techniques and 15 tactics, with revoked and deprecated flags and a map from revoked ids to their successors.

#### Documentation and tests

- **The documentation is executable.**
  `tests/test_docs.py` runs every block marked runnable, parses every `threatcode` command in the docs against the real CLI, loads the rule-file examples beside the built-in rules, checks the CI recipes and the Bitbucket upload helper, and proves the harness fails on a broken snippet.
  `scripts/gen_docs_counts.py` generates the counts, the rule catalog, the support matrix, the CLI tables, the ATT&CK tables, the resource limits, the example reports and the benchmark from the code, and `--check` fails when a page drifts.
- **New pages:** a CLI reference, a support matrix, a benchmark, a rule catalog, a security model, a migration guide from 0.9, a release checklist and a page that maps every public claim to a command or test.
  `SECURITY.md` describes private vulnerability reporting.
- **A planted-issue benchmark** (`tests/test_quality`) scores the ten realistic fixtures through the same pipeline as `scan`: 37 of 39 planted issues found, no finding on hardened resources, and a ratchet that keeps it so.
- **Three demo stacks** (`examples/aws-webapp`, `examples/k8s-platform`, `examples/agent-workstation`) with READMEs, expected paths and tests.
- **Final quality gates** in `tests/test_meta.py` fail the build when a test carries a pending marker, when a rule has no example case, when a rule or attack path uses a missing, revoked or deprecated ATT&CK technique, when a rule's resource type has no catalog category, when a test asserts nothing, or when a test accepts a range of exit codes.
  Every parser and enrichment module exports `PRODUCED`, the properties it can write, and `tests/test_engine/test_rule_property_provenance.py` fails when a built-in rule reads a property that nothing produces.
  `tests/test_properties.py` holds hypothesis properties for the Helm fallback tokenizer, the Dockerfile lexer, the secret preview, `base_address` and SARIF output.
  `ruff` selects B, BLE, S, ARG, SIM, C4 and C901 (threshold 15) for `src`.
- **Test infrastructure:** a per-rule bad and good example for every built-in rule, a format-parity test, a real-shape corpus of Terraform plans, templates, manifests, charts, Dockerfiles and MCP configs, a hardened corpus that must scan clean, schema conformance tests for SARIF and Navigator layers, hostile input generators and property tests, golden recordings per input, and a `pending(package, reason)` marker.

### Changed

#### Breaking changes

- **The default `--fail-on` is `high`.**
  Before, any finding made `scan` exit 1.
  A scan whose worst finding is medium or lower now exits 0; `--fail-on info` restores the old behavior and `--fail-on none` never fails on findings.
  With the default, a scan of an input with a public bucket, or with a path from the internet to a database, exits 1.
- **Errors exit 2, not 1.**
  A parse failure, an unreadable file, a bad config and a missing output path used to exit 1, the same as a finding.
  A file a parser claims but cannot parse is no longer skipped, and a scan that parsed nothing no longer prints a "0 findings" summary.
- **The LLM is opt-in and the model client is an optional extra.**
  A model is contacted only with `--llm`, `THREATCODE_LLM=1` or `llm.enabled: true` in a config named with `--config`, and only with `pip install "threatcode[llm]"` (or `threatcode[all]`).
  An exported `ANTHROPIC_API_KEY` no longer sends a redacted graph anywhere by itself, `--dry-run` implies `--llm` and sends nothing, and `--dry-run` with `--no-llm` is a usage error.
  `anthropic` moves out of the required dependencies, as do `httpx` and `packaging`, which are dropped.
- **The default model is `claude-sonnet-5-5`.**
  The reply is the joined text of every text block, `llm.temperature` is unset by default and sent only when set, and `ANTHROPIC_BASE_URL` and `llm.base_url` go through the same address check as the other providers.
- **`-f matrix` is now `-f navigator`.**
  `matrix` still works as a deprecated alias and will be removed in a later release.
- **The report always carries `schema_version`, `attack_paths` and `coverage`,** and `input_file` and `location_file` are POSIX paths relative to the scan root.
  The summary counts and the severity filter use the effective severity.
- **Python API:** `scan(input_path, no_llm=..., output_format=...)` became `scan(paths, **settings)`.
  Passing `output_format` is a `TypeError`; `threatcode.formatters.render(name, analysis)` renders other formats.
- **Config keys:** `no_llm` and `dry_run` were never read and are removed, a file that still has them fails with a message that says what replaces them, and `output_format` accepts the names in the format registry (`cyclonedx` is gone).
- **Rules match their resource type exactly.**
  A rule with `resource_type: aws_s3_bucket` no longer also runs on `aws_s3_bucket_versioning` and the other companion resources.
  Use `resource_type: "aws_s3_bucket*"` or an explicit `resource_types` list for a family.
- **Edges exist only because the input names their target.**
  The "first VPC" heuristic and matching on `node.name` are gone, and a literal `vpc_id` binds only when the input has exactly one VPC.
  A security group attachment is a `dependency` edge with relation `security_group` for every input, not a `network_flow`.
- **Zones follow the category,** and a public data store stays in the `data` zone with `exposure: internet`, so it can be the end of an attack path.
- **Cluster-scoped Kubernetes kinds have no namespace in their address** (`kubernetes_cluster_role.admin`, not `kubernetes_cluster_role.default.admin`).
  A suppression, baseline or diff that names the old address must be updated.
- **Boundary findings are one per traffic flow with unique ids,** and their fingerprint names both ends, so a baseline written before this release shows its boundary findings as new once.
- **CloudFormation resource types are named by a complete table:** `AWS::CloudTrail::Trail` is `aws_cloudtrail`, `AWS::Logs::LogGroup` is `aws_cloudwatch_log_group`, and 140 more.
  Properties are the translated names, so code that read `properties["AccessControl"]` reads `properties["acl"]` or `properties["_cfn"]["AccessControl"]`.
- **Project-scoped MCP servers in `~/.claude.json` are addressed `mcp_server.<project>-<8 hex>.<server>`,** so two projects with the same basename no longer collide.
- **Terraform plan resources have an empty `module` field** (the instance is in `meta["module"]`), and an `Unknown` the plan parser places is falsy.
- **Error messages drop the exception class name,** and a ThreatCode error prints `Error: <message>` and exits 2.

#### Findings and severities

- **Severities were recalibrated against one convention** (absence rules at most medium, heuristic rules at most high, critical only for definitive exposure of data or control).
  Among the moves: `S3_NO_ENCRYPTION`, `CLOUDTRAIL_NO_ENCRYPTION`, `DYNAMODB_NO_ENCRYPTION`, `SQS_NO_ENCRYPTION`, `SNS_NO_ENCRYPTION` and `SM_NO_KMS_KEY` high or medium to low (S3, DynamoDB and SQS encrypt by default, so these are the customer-managed key preference), `IAM_OVERPERMISSIVE_ROLE` high to critical, `ECS_PRIVILEGED_CONTAINER` critical to high, `K8S_RUN_AS_ROOT` and `K8S_ALLOW_PRIVILEGE_ESCALATION` high to medium, `K8S_CLUSTER_ADMIN_BINDING` critical to high (critical only for anonymous subjects), `DOCKER_NO_USER` high to medium, `DOCKER_ENV_SECRET` and `DOCKER_ARG_SECRET` critical to high, `GKE_NO_PRIVATE_CLUSTER` high to medium and `ES_PUBLIC_DOMAIN` critical to high.
  A bare S3 bucket therefore no longer fails the default gate.
- **Missing logging and detection controls are STRIDE repudiation and claim no ATT&CK technique,** which replaces the revoked T1562.008 on every rule that carried it, and recoverability controls are denial of service.
  The hand-written `tactics:` lists are gone from the built-in rules and are derived from the techniques.
- **Many rules were rewritten to read what the input really holds.**
  Security group rules read the real list-of-objects `ingress` (`SG_UNRESTRICTED_INGRESS` no longer fires on nothing, and `SG_WEB_PORT_OPEN_TO_WORLD` takes the public load balancer case at low); S3, IAM, KMS, SQS, SNS, RDS, CloudTrail and Config rules read companion resources and parsed policies; Azure network security group rules look at source, direction and port; GCP firewall rules look at port, direction and source; Cloud SQL, Cloud Run and BigQuery rules read the settings where Terraform puts them; Kubernetes rules read the effective security context, NetworkPolicy coverage and service account token mounting; the WAF, ECS and EKS rules read the attributes that exist.
  The full list is in the [rule catalog](docs/rules.md).
- **Operators are stricter:** `equals` does not coerce, `is_true` reads `"false"` as false, comparisons take numeric strings and refuse booleans, `contains` with a non-string argument is false instead of a `TypeError`, and a condition nested too deeply is rejected at load time.
- **Plan JSON agrees with HCL about empty blocks:** `None`, `""`, `[]` and `{}` count as absent, `false` and `0` as present.
- **`GCFUNC_HTTP_NO_AUTH` is retitled "HTTP trigger allows plain HTTP"** and lowered to low (the real unauthenticated check is `GCFUNC_PUBLIC_INVOKER`), `WAFV2_*` protection rules moved from rule groups to web ACLs, and `LAMBDA_NO_VPC` is a low isolation note.

#### Formats and behavior

- **Markdown severities are text labels** (`[CRITICAL]`), not emoji shortcodes, and the `text` report has a new layout with a verdict line and a table.
- **`-o` writes the report and says so on stderr,** so stdout stays empty, and a directory or an unwritable path is one `Error:` line and exit 2.
- **`-f json` writes sorted threats.**
- **`threatcode diff` compares ids as multisets,** reports a changed severity or title, and is sorted by severity.
- **`coverage.suppressed` and `coverage.baselined` count findings and attack paths together.**
  The `Using ignore file` line on stderr says how many of each were suppressed, for example `suppressed 2 findings and 1 attack path`, and `ScanResult` has two new integers, `suppressed_paths` and `baselined_paths`, for the paths among them.
- **The core install is smaller,** the version is single-sourced from `threatcode.__version__`, the wheel ships `py.typed`, and Python 3.14 is a declared classifier.
- **The wheel smoke test compares instead of counting:** the packaged rule files must equal the checkout's and the loaded rule ids must equal the ids in the source.
- **Releases are gated on CI,** the release tag is checked against the version in the built wheel, and CI runs on every pull request with a matrix of Python 3.10 to 3.14 on Linux plus one macOS and one Windows job.
- **The GitHub Action no longer ends with `|| true`.**
  It captures the exit code, fails the job on exit 2 at once and on exit 1 after the report is written and uploaded, handles paths with spaces, and its SARIF upload is pinned to a commit that exists.
  The install wording stays at the Git URL until PyPI returns 200.
- **Provider defaults that a plan materialises** (for example an EKS cluster's public endpoint) are applied to Terraform HCL and CloudFormation input only, never to a plan or a design.
- **Loaded rules are immutable** and the built-in rules are parsed once per process.

#### The text report

- **The terminal report never cuts a name.**
  The RESOURCE, RULE and FINDING cells used to end in `...` or lose their middle (`aws_in...ce.app[0]`), so rows could not be told apart and a rule id could not be pasted into `.threatcodeignore`.
  A cell wider than its column wraps after a dot or a slash, so every resource address, rule id, file and line is printed whole at any width from 40 columns up.
  A technique list ends in a count (`T1548,T1611,T1105 +2`) instead of cutting an id in half, and a column that no finding fills is left out.
- **Each finding is a block that reads the same way every time.**
  The first line is the severity, the resource, the rule and the attack paths it enables.
  The second is the finding, wrapped with a hanging indent.
  The third, dim, holds the location, the ATT&CK techniques and the STRIDE category in columns that line up from one finding to the next: `tfplan.json:484  T1552.005  EoP`.
  The header names the same columns, and on a terminal too narrow to line them up they flow in the same order.
  A location wraps after its slashes only, and a line number is never left alone at the start of a line.
- **The rule moves under the resource, for the whole table, when the two do not fit side by side.**
  The layout is decided once from the widest cell of each column, so one table never mixes the two shapes.
  A rule id keeps a line to itself before it is wrapped, and the severity stays with its rule id when a line wraps.
- **The heading reconciles with the rows.**
  `Findings (30, 23 rows after grouping)` says that findings with one root cause on one resource share an entry, and the entry lists the other rules in full on an `also` line.
- **A severity changed by context is marked.**
  `HIGH^` was raised from the rule's own severity and `v` was lowered, a key under the findings says so, and the key is set apart by a blank line.
  A finding that enables an attack path carries the number of the path (`P1`, `P1,P2+1`) and sorts first inside its severity band.
  The severity column is as wide as its widest mark, so `CRITICAL^` no longer pushes its row aside.
- **Attack paths say why they exist.**
  The report numbers the paths, gives the target kind, the length, the score (one decimal) and the worst enabling finding in one sentence, counts the equivalent routes through other instances, and lists for each step the findings that enable it by rule id and effective severity, with the port the step uses: `internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD`.
  Up to three findings are named per step, then `+N more`, and findings that a filter or a baseline removed are counted as `+N not shown`.
  The path id is labelled `ignore id`, because it is the key a `.threatcodeignore` entry or a baseline uses.
- **The verdict names what a path ends at and how bad the worst one is.**
  `2 attack paths from the internet to private` is now `2 attack paths from the internet to private data, worst high`.
  The verdict is shared with the Markdown report.
- **A scan that failed or fell short never reads as clean.**
  With an input error the verdict says `no result (1 input error; nothing was analysed)` or `incomplete (1 input error); in the rest: ...`, never `no findings`.
  A chart that lost templates reads `incomplete (2 templates not analysed); in the rest: 5 medium, 9 low`, and a chart with nothing else to report reads `incomplete (1 template not analysed); in the rest: nothing found`.
  Gaps that only approximate (a chart rendered without helm) or that describe a module the scan was not asked to read do not change the verdict; the coverage block lists them.
  When a baseline accepted everything it says `no new findings (6 findings and 2 attack paths baselined)`.
  The closing `Scanned ...` line on stderr says `incomplete` when a Helm template was skipped or only approximated, or an error-level gap exists.
- **`--min-severity` says what it hid.**
  The header reads `0 of 12 findings shown`, the coverage block has a `Hidden: 12 findings and 2 attack paths below critical (--min-severity)` line, and the `Scanned` line on stderr repeats it.
  `Set aside` counts findings and attack paths apart.
- **The coverage block names the files no parser recognised:** `Not infrastructure: expected.yml, scanner/trivy-app-image.json`, the first five by name and the rest counted.
  A scanner finding that matched no resource reads `(unmatched)` in the RESOURCE column, where it read `-`.
- **Coverage gaps and input errors are said once.**
  With the text report on standard output stderr keeps one line for the gaps and the last line for the exit code, because the report already lists them; every other format, and `-o`, keeps the full list on stderr.
  A gap that repeats with the same code, file, line and message is listed once (in `coverage.gaps` too), a file's many gaps of one code are one line with a count, and a repeated error is dropped from `coverage.errors`.
  A gap whose message already starts with its file name is not given the file twice.
  The `Scanned ... found ...` line is left out when the text report went to standard output, because the header says the same.
- **Every nonzero exit says why, on the last line of stderr.**
  Exit 2 ends with `Error: scan incomplete (1 input error), exiting 2: <the first error>`.
  Exit 1 ends with `Gate failed: 5 findings and 3 attack paths at or above high (--fail-on high), exiting 1`, counted before `--min-severity` hid anything.
- **Long lines wrap with a hanging indent.**
  On a terminal the width is the terminal's; into a pipe or a log stderr messages stay on one line, so a tool that reads the last line gets all of it.

#### Other reports and the diagram

- **A boundary title leads with what tells crossings apart.**
  `Trust boundary crossing: aws_lb.front (dmz) -> aws_instance.app[0] (private)` is now `dmz > private: to aws_instance.app[0] (tcp/8080)`, with `, unencrypted` or `, unauthenticated` when the input says so.
  A crossing prints its kind in the RULE column (`BOUNDARY_GENERIC_FLOW`, `BOUNDARY_UNENCRYPTED_FLOW`, ...), which is also the id a suppression accepts, and the descriptions say `data flow` and `network flow` where they said `(network_flow)`.
  The title in the JSON report is the new one.
- **Edges and hops are described in words in every report.**
  `network_flow 443`, `iam_binding invokes` and `data_flow returns_content` read `HTTPS 443`, `invokes` and `returns content` in the diagram, the Mermaid charts, the Markdown report and the SARIF code flows (`sends traffic on tcp 8080`, `assumes the role`).
  Markdown "enabled by" lines and the diagram's enabler captions name a boundary finding by its rule (`BOUNDARY_GENERIC_FLOW`) instead of `boundary`.
- **Attack paths are the one emphasised thing on the diagram.**
  The hops of an attack path are thick, glow, and take the color of the worst path over them.
  A flow that crosses a trust boundary keeps the look of its type (blue dashed for traffic, green for data) and carries a zone label, and a reference or an IAM binding that only spans two zones is a thin grey line.
  A hop the graph has no connector for is drawn too.
- **Path numbers are the same everywhere.**
  A path number is an outlined square (`P1`, `P1 P3`, or `P1-P3` for a run) kept off nodes, badges, labels and zone lines, and the legend has an entry for it.
  The diagram, the Markdown report, the terminal report and SARIF number the paths by worst severity, then score, then path id, so two paths that tie no longer swap places between reports.
  The strips shown are the first five of the Markdown list.
- **The diagram labels are readable and unique.**
  One zone label per transition (`DMZ -> PRIVATE x7`, with the connectors in the tooltip), both ends named in every connector tooltip, and two edges between the same nodes drawn as one connector.
  Nodes that share a name take the short type in front (`role.app`, `sg.app`, `ingress/storefront`), a VPC with members in three zones says `aws_vpc.main (internet)`, `(dmz)` and `(private)`, and type captions are 9px in a 176 pixel box and cut in the middle only past 31 characters.
  The ids of one diagram differ from the ids of another: the prefix is a hash of the input name, the resources, the findings and the paths, so two reports in one HTML page no longer collide.
- **A data store's settings are folded into it on the diagram.**
  `aws_s3_bucket_public_access_block` and the encryption configuration were two more cylinders labelled like the bucket.
  Their findings count on the bucket's badge and its tooltip lists them.
- **The legend matches the shapes,** and has four columns with entries for attack path hops, path numbers and boundary crossings.
  Network and delivery components are boxes with a dashed outline, and the internet is an external entity.
- **Attack path strips say everything the path says.**
  The rationale wraps to three lines, each box holds the full address, each hop lists every finding that enables it (up to three, then a count), ATT&CK ids sit under their hop, and arrows say `HTTPS 443`, `assumes`, `invokes` and `can read`.
- **The findings table groups, cuts at a sentence and says where.**
  Findings with a root cause on one resource are one row, the description is the first sentence of the rule's text, and a new Location column gives `file:line`.
  The rows are in the text report's order: worst first, then the findings that enable an attack path, then resource and rule.
  The diagram is at least 968 pixels wide.
- **Frame labels are readable.**
  Labels are drawn above the connectors on a backing and slide along the top of their frame to the first spot no connector crosses.
  The router also moves the port of a framed node, and the vertical run through a column gap, out from under labels and badges.
  A frame with no free spot drops the zone part of its label (`aws_subnet.public_a`) and then characters from the middle, and the full name stays in its tooltip.
  Zone titles are a dark variant of the hue, and a test measures the contrast of every text of the three examples against its background (4.5 to 1).
- **Wide attack paths widen the lanes,** using up to eight columns of the canvas.
- **Mermaid charts run top to bottom** (`flowchart TB`; the aws example is 919 pixels wide where `LR` drew 3213).
  Edges between the same two resources share one arrow with their labels joined, opposite directions share one arrow with a head at each end, and another instance of a counted resource that a path runs through has a dashed red outline.
  A path segment that every address shares is replaced by `...` so long addresses keep their resource name.
  The chart in the Markdown report draws the hops of the attack paths only, and a comment line and a line above it say so.
- **Markdown report details.**
  Shared hops are listed once (`Hops 1 to 4 are the same as in path 1`), sections are ordered by their worst effective severity, headings drop the resource when the title already names it, and group titles start with a capital.
  The severity explanation is one clause (`Medium (base low, raised one level because the data store is tagged ...)`).
- **A web address in Markdown is a code span, not text with an invisible character.**
  The report used to put a zero-width joiner inside `://` to keep GitHub from linking an address, which broke a copied address.
  An address in a code span copies exactly, with trailing punctuation left outside it, in the Markdown report, the diff report and the Markdown in SARIF rule help.
  Mentions and issue references still get the joiner.
- **SARIF and Bitbucket name files from the repository root, wherever the scan was started.**
  The repository root is the git top level above the scan root (`.git` as a directory or a file), so `cd examples && threatcode scan aws-webapp -f sarif` writes `examples/aws-webapp/tfplan.json`, which GitHub can place.
  A scan root in no checkout is a `sarif.paths.unanchored` notification and a file outside the repository is `sarif.paths.outside_repository`; such a file is named by its file name alone, and no absolute path of the machine reaches the report.
  The Bitbucket report mentions files it could not place in `report.details`.
- **A SARIF rule has one severity.**
  A finding whose effective severity differs from its rule's belongs to a variant rule `<id>/<severity>` (`EC2_IMDSV1/high` beside `EC2_IMDSV1`) with the level and `security-severity` of that severity, and the bare id keeps the rule's highest base severity.
  Alerts that context raised or lowered move to the variant id once, and GitHub shows them as new alerts.
  Attack paths follow the same rule (`THREATCODE_ATTACK_PATH` and `THREATCODE_ATTACK_PATH/high`).
- **A SARIF result message is one sentence about the instance** (`EC2 instance metadata service allows IMDSv1 on aws_instance.app[0]`), with the first sentence of the description added for crossings, scanner findings, secrets and model findings; the rest stays in the rule's `fullDescription` and `help`.
  Rule names are made from the id (`CVE-2022-37434`, `K8SNoSeccompProfile`) and the rule id `trivy:trivy:CVE-2022-37434` is `trivy:CVE-2022-37434`.
- **SARIF attack paths are anchored where the fix goes.**
  The result is anchored at the first resource of the path that has a file, a hop with no file (the internet) is shown at the resource it enters, and hop messages name the ports and the enabling rule ids.
- **A SARIF run says what it left out and what it was joined to,** in note-level notifications: `suppressions.applied`, `baseline.applied`, `min_severity.hidden`, one `ingest.source` per scanner result and `llm.ran`.
- **The Navigator layer draws a technique once per path step.**
  The entry step is initial access and a later step takes the tactic that brings the attacker closest to the target; a finding that names its tactic keeps it.
  The gradient has five stops at the five legend colors, and the description counts only the threats that name a technique.
- **Bitbucket: `report.result` follows the gate and annotations are short.**
  The result is `FAILED` when a finding or attack path at or above `--fail-on` remains (model findings never count), so `--fail-on none` is `PASSED`, and an annotation is the resource, the reason for the severity and a mitigation cut at 300 characters.
- **The GitHub Action** lists the formats the CLI advertises in its `format` input (a test keeps the list equal to the registry), names the report file from the format registry (`threatcode-results.mmd` for Mermaid), finds its sticky comment by the marker anywhere in the body, and has a `code-scanning` job that uploads the SARIF of `examples/aws-webapp` on pushes to `main`.
  CI checks that the SARIF the action writes names files from the repository root.

#### Findings, attack paths and paths in reports

- **`K8S_RBAC_SECRETS_READ` is a definitive finding** (confidence 1.0).
  A rule that names its objects with `resourceNames` is a narrow grant and sets neither `has_secrets_read` nor `has_pod_exec`, so the description no longer says the rule cannot tell.
- **An MCP server with no credential in its configuration is not called unauthenticated.**
  The edges carry `authenticated: true` when a header, an `oauth` block or credentials in the URL show a credential, and no flag otherwise, because a client that follows the MCP authorization spec discovers OAuth when it connects.
  A flow whose only open question is that sign-in keeps the confidence of an absence (0.5) and at most the severity of `MCP_REMOTE_NO_AUTH` (low), so a lone `.mcp.json` over https exits 0.
  A server over plain http stays a definite high finding, now classed as information disclosure like `MCP_PLAINTEXT_TRANSPORT`.
  A design input that declares such a flow unauthenticated is believed.
- **An attack path attaches a finding to the one hop it opens.**
  `hops[].enabled_by` lists the security group that admits the internet once, on the first hop; the path's severity, rationale and the findings' `path_ids` are unchanged.
- **Kubernetes findings point at the key they are about.**
  `K8S_PRIVILEGED_CONTAINER` on `examples/k8s-platform/daemonset.yaml` is at line 23, the `privileged: true` of the container that sets it, where nearly every Kubernetes finding was at line 1.
  A finding about something missing points at the object that should hold it, a finding about the whole object points at its `kind:` line, a secret keeps its line, and a manifest with no text keeps the line of its document.
- **A finding names its resource type,** including a secret finding, whose `resource_type` was empty.
- **Paths in a report are relative to the scan root, whatever they point at.**
  A Terraform module in a parent directory (`source = "../modules/net"`) reported its findings with the absolute path of the machine; it is now `../modules/net/main.tf`, so fingerprints and baselines survive a clone elsewhere.
- **A local module directory is in the report once.**
  `modules/vpc` and `module "vpc" { source = "./modules/vpc" }` in its parent read the same files, so scanning the repository listed every resource twice.
  A directory whose every resource another module reads is no longer put in the graph on its own, a `graph.unit_superseded` note says so, and its files are still scanned for secrets.
- **A rule file that names a revoked ATT&CK technique is warned about,** with the technique that replaced it (or the note that a deprecated one has no replacement); the rule still loads.
- **Rule texts name no internal property.**
  `K8S_PRIVILEGED_CONTAINER` no longer sends the reader to `container_findings` and `MCP_UNPINNED_PACKAGE` no longer sends them to `unpinned_reasons`, and a test fails when a built-in rule's title, description or mitigation names a property a parser writes or an edge type.

#### Command line and configuration

- **The version is 1.0.0.**
  `threatcode --version` and the `version` field of a report tell the reworked line from 0.9.1, which stays the release on PyPI until the first release of this line is published.
  `CHANGELOG.md` keeps its Unreleased heading until then, and `docs/releasing.md` says what to move at release time.
- **The config keys are `format` and `rules`,** the names of the `--format` and `--rules` flags.
  `output_format` and `extra_rule_paths` still load and print a notice that names the new spelling, giving both spellings of one key is an error, and an auto-discovered `.threatcode.yml` may set `format` and still cannot set `rules`.
  `docs/configuration.md` has one table of the name each setting has as a flag, an environment variable, a config key, an Action input and a `scan()` argument.
- **`-f matrix` is hidden from `--help` and from the invalid-value error but still accepted.**
  Every use prints `Warning: -f matrix is deprecated, use -f navigator` on stderr, once, even with `-q`; rendering it through the API logs the same on the `threatcode` logger.
  The alias renders the layer of `navigator`, and only the migration page names it.
- **`--format` shows a short `FORMAT` metavar** with the formats and the default in its description, `--max-nodes` and `--max-edges` state their defaults (10,000 and 50,000), and `diff --fail-on-new` takes the same choices as `scan --fail-on`, including `none`.
- **`-f diagram` and `-f navigator` are refused when standard output is a terminal,** before the scan runs, with the `-o file` form to use instead.
- **`--llm` checks for the anthropic SDK before it says anything about sending.**
  Without the SDK it is one exit-2 line that names `pip install 'threatcode[llm]'`, with or without a key; without a key the scan continues with rules only, and the `LLM enrichment enabled: sending ...` line is printed only when a request can be sent.
  `--dry-run` needs neither.
- **The Environment block is one list** shared by the main help and the help of `scan` and `diff`, so `scan --help` lists `THREATCODE_MAX_NODES`, `THREATCODE_MAX_EDGES` and `THREATCODE_DEBUG` too.
- **`threatcode diff` lists findings in the order of the report:** severity, resource address, rule id and id.
  The text format pads the severity and resource columns so every title starts in one column.
- **Rules keep their reading of the input.**
  The `_exposure` pseudo-property in a rule condition reads the exposure the graph decided for the node, `metadata.cwe` and `metadata.cis` are validated at load time, and a Secrets Manager ARN written as `name-*` or `name-??????` names the secret.

#### Documentation

- **The documentation describes the build it ships with.**
  The getting-started walkthrough explains the text report as printed, and the CLI reference, the CI page and the migration page state what the SARIF writer, the Bitbucket report, `-o`, the options after the command and the removed commands do.
  The ATT&CK page explains the Navigator layer as drawn and lists the four `BOUNDARY_*` kinds, and the rule-writing page documents `_exposure` and the MCP agent node.
- **The support matrix has a Coverage gaps section** that lists the gaps a scan can report with what raises each and what to do, including `hcl.default_disabled` and `enrich.unresolved_companion`.
  It also says that an unparseable file that looks like a plan, template or manifest is an input error, and how the multiline secret rule and the templated-file argument behave.
- **A new `CONTRIBUTING.md`** covers setup, the checks, tests, the generated documentation, golden recordings and the changelog.

### Removed

- **The scanning layer that duplicated Trivy, Grype, Syft and OSV-Scanner.**
  ThreatCode builds threat models and attack paths and does not compete with scanners on breadth.
  The `image`, `vuln`, `db`, `sbom`, `license`, `repo`, `fs` and `secret` commands are gone, so the CLI has two commands, and `scan` loses `--scanners` and `--ignore-unfixed`.
  To scan a repository, clone it and run `threatcode scan <dir>`; to scan an image or a lockfile, run a scanner and pass its result to `--ingest`.
- **The functions and modules behind them:** `scan_secrets`, `scan_vulnerabilities`, `scan_all`, `scan_filesystem`, `scan_repository`, `scan_image`, `LOCKFILE_NAMES`, `cvss_to_severity`, the image scanner (registry client, layer extractor, OS detection, package parsers), the OSV database and OS advisory downloaders, the license scanner, CycloneDX output, the lockfile parser, `SecretFinding`, `VulnerabilityFinding`, `LicenseFinding`, `ScanReport` and `FindingType`.
  The image scanner extracted layers to disk and could be steered into deleting files on the host through whiteouts and symlink chains, and the OSV matcher compared versions with a range model that gave wrong results.
- **`threatcode.ignore`** (`load_ignore_ids`, `apply_ignore`) is replaced by `threatcode.suppressions`.
- **The `property_path` rule operator,** which ignored the key it was written under and which no built-in rule used.
- **Stale files:** the root `threat_model*.svg` renderings, `tests/fixtures/realistic/output/`, `bitbucket/pipe.yml` (a commented-out file that is not a pipe) and `OWASP_AUDIT_REPORT.md`.
- **The following 29 rule ids** were removed because the condition they tested did not describe an attacker's opportunity, tested an attribute that does not exist, or duplicated another rule.
  Each is listed in `deprecated_ids` of its rule file, so a `.threatcodeignore` line that names one warns instead of silently doing nothing.
  AWS: `CLOUDTRAIL_NO_S3_ACCESS_LOGGING`, `CONFIG_NO_AGGREGATION`, `CONFIG_NO_DELIVERY_CHANNEL`, `DYNAMODB_NO_AUTOSCALING`, `EC2_NO_MONITORING`, `EKS_NO_FARGATE_LOGGING`, `EKS_PUBLIC_NODE_GROUP`, `EKS_UNENCRYPTED_NODE_AMI`, `IAM_NO_MFA`, `KMS_NO_DELETION_PROTECTION`, `KMS_WILDCARD_POLICY` (merged into `KMS_KEY_EXPOSED`), `LAMBDA_NO_DLQ`, `SM_NO_RESOURCE_POLICY`, `SQS_NO_DLQ` and `SSM_STANDARD_TIER_SECRET`.
  Azure: `AZURE_SQL_NO_ENCRYPTION`, `AZURE_SQL_PUBLIC_ACCESS` (use `MSSQL_NO_TDE` and `MSSQL_PUBLIC_ACCESS`), `AZURE_VM_NO_EXTENSIONS`, `COSMOS_NO_ANALYTICAL_STORAGE`, `FUNC_HTTP_V1` and `KEYVAULT_NO_SOFT_DELETE` (use `KEYVAULT_SHORT_SOFT_DELETE_RETENTION`).
  GCP: `BQ_NO_LOCATION`, `PUBSUB_NO_DEAD_LETTER` and `PUBSUB_NO_RETENTION`.
  Kubernetes: `K8S_NO_LIVENESS_PROBE`, `K8S_NO_PDB`, `K8S_NO_READINESS_PROBE` and `K8S_NO_RESOURCE_QUOTAS`.
  Docker: `DOCKER_EXPOSED_PRIVILEGED_PORT`.

### Fixed

- **A parse failure no longer produces a report that looks clean.**
  The failing file is named in `coverage.errors` and on stderr, and the scan exits 2.
- **Terraform state was scanned as an empty plan.**
  `terraform show -json` without a plan file prints state, so a CI gate built from the documentation reported `Scanned 0 resources` and passed forever.
  State JSON and destroy-only plans now fail with the command that fixes them.
- **A scan of a repository that only used modules reported a clean pass,** because `module`, `data`, `variable` and `locals` blocks were ignored.
- **Absence rules fired on every CloudFormation resource and value rules never fired on CloudFormation,** because the rules read Terraform attribute names that a template does not have.
  38 false findings disappear from the three realistic templates and the public bucket, public database and wildcard policy of a template are found.
- **Rules that read inside nested blocks never matched real Terraform shapes** (`CLOUDSQL_*`, `APPSVC_OLD_TLS`, `WAF_*`, `CLOUDRUN_*` and more), and `K8S_NO_PSA_LABELS` fired on every namespace because the label key contains dots.
- **False positives on hardened input:** the pod-level `seccompProfile`, a default-deny NetworkPolicy, a ServiceAccount that disables token mounting, multi-stage Dockerfiles, lowercase instructions and heredocs are all read correctly.
  A hardened Kubernetes workload, Dockerfile and MCP config scan with no rule finding.
- **Multi-document Kubernetes manifests were skipped** because YAML was loaded with `safe_load`; YAML is now read with `safe_load_all`.
- **A duplicate resource address no longer overwrites the first resource;** later ones are kept as `<address>#2` with a warning.
- **Edge order changed between runs** because dependencies were deduplicated through a set.
- **A crash inside a parser was reported as "Cannot detect format";** it is now `<parser> parser failed on <file>` with the original exception attached.
- **Files with a byte order mark** failed with `Unexpected UTF-8 BOM` or broke the first Dockerfile instruction.
- **A few short lines could hang the scan, exhaust memory or crash it:** locals that double at every level, a chain of 100 locals, `dynamic` blocks nested inside each other, and a file nested too deeply.
  They finish in under a second, and a value past a limit is `Unknown` with a warning that names the limit.
- **The Helm fallback renderer** crashed on the `helm create` scaffold, dropped templates in subdirectories and subcharts, and ran after a failing `helm` with only a debug message.
- **Secret findings:** line numbers no longer shift on a form feed, UTF-16 files are decoded, and a keyword prefilter that was case-sensitive no longer skips `MasterUserPassword`.
- **`mypy` passes on `engine/llm/client.py`** with the installed Anthropic SDK.
- **Suppression notices:** line numbers no longer shift on a form feed, and CRLF files and files with a byte order mark read like plain ones.
- **Attack paths honor `--baseline`, `--write-baseline` and `.threatcodeignore` in `threatcode scan`.**
  Before, an attack path gated the exit code but nothing could set a known one aside: `threatcode scan infra/ --write-baseline base.json` followed by `threatcode scan infra/ --baseline base.json` removed every finding and still exited 1 on the same attack paths.
  The baseline now records the id of every attack path beside the fingerprints, `--baseline` removes the paths it lists from the report and the gate, and a new path still fails the gate.
  A `.threatcodeignore` entry that names an attack path id suppresses that path, with `resource=` narrowing it to a path that crosses a matching resource.
  The suppression of paths and findings happens before the gate, so a fully suppressed scan exits 0.
- **Scanner findings that ThreatCode already reports are dropped.**
  With `--ingest`, a scanner secret at the file and line of a native secret finding, or a scanner misconfiguration at the file and line of a native rule finding, was reported twice.
  The scanner finding is now dropped, the native finding lists the tool in `metadata.corroborated_by`, the dropped finding is counted in the `duplicates` of its entry in the report's `ingest` list, and an `ingest.duplicate` info diagnostic names it in the graph diagnostics.
  Attack path hops and findings that referred to the dropped finding now refer to the native one, so no `enabled_by` entry names a finding the report no longer holds.
  Vulnerabilities have no native counterpart and are never dropped.
  The match is by file and line only, so a scanner misconfiguration on the first line of a resource is dropped whenever ThreatCode has a rule finding on that resource.
- **A removed-rule warning for user rule files.**
  An ignore entry that names a rule listed in the `deprecated_ids` of a rule file passed with `--rules` now gets the "removed or renamed" warning, as it already did for the built-in rule files.
- **Rule findings carry their rule's confidence** (definitive 1.0, heuristic 0.7, absence 0.5) **and root cause.**
  Before, every finding reported confidence 1.0 and no finding was grouped by root cause, so the SARIF precision of a heuristic or absence rule was always high.
- **A Dockerfile word or a Helm string of several megabytes** no longer takes memory in proportion to 150 bytes per character.
  One five megabyte word peaked at 1.5 GB and now peaks at 69 MB, and the findings are identical.

#### Input errors and parsing

- **A file that fails to parse is an input error wherever it sits.**
  A Terraform file that could not be parsed exited 2 when named on the command line and 0 when it sat in a directory next to a file that parsed, so `threatcode scan infra/` could report 227 failed files and still pass.
  Both cases list the failure under the coverage errors once, add "incomplete: N input errors" to the closing line, and exit 2.
- **A truncated plan fails the scan.**
  A `plan.json`, `tfplan.json`, `*.tfplan.json` or `plan-*.json` that is not valid JSON, and any JSON or YAML file whose first lines read as a Terraform plan, a CloudFormation template or a Kubernetes manifest, is a parse failure, so a half-written `terraform show -json` in CI exits 2.
  Template delimiters (`{{ .Values.x }}`) and files that say nothing about infrastructure still count as not infrastructure.
- A directory whose only resource file fails to parse reports that failure, and "1 input was parsed" appears only when a scan finds no resources and nothing failed.
- **A Rain module says what it is.**
  A CloudFormation resource of type `!Rain::Module <path>` reads "Rain module not expanded (run rain pkg to expand it)" and marks the template incomplete, where it was skipped with "Type must be a string, not a dict".
- **Valid Terraform that python-hcl2 rejected now parses.**
  python-hcl2 4.x rejected an object element whose value is an operator expression, a conditional that breaks its line before `?` inside nested parentheses, and a `\r\n` inside a block comment; 8.x rejected a traversal that continues on the next line.
  A file that fails is retried with its layout normalized, and if the retry fails too the error names the line of the original text and, under 4.x, the command that upgrades python-hcl2.
  On cloud-foundation-fabric under 4.3.5, 90 failing files now parse, and 3026 resources with 29 findings became 5088 resources with 41 findings.
- **python-hcl2 4.x keeps the parentheses of a grouped expression.**
  4.x returns `a && (b || c)` as `a && b || c`, which changes what a `count` or a condition evaluates to; terraform-aws-vpc modelled 1758 resources under 4.x and 1686 under 8.x.
  Grouping parentheses now travel through 4.x as a marker call, and 4.x and 8.x agree on the nodes, properties, findings and gaps of cloud-foundation-fabric, terraform-aws-eks, terraform-aws-vpc and terraform-aws-eks-blueprints.
  The dependency range stays `>=4.3,<9`.
- Terraform text is parsed once per run.
  The parser keeps the data of recent texts (8 million characters, oldest dropped first), so cloud-foundation-fabric takes 11 seconds where it took 27 and terraform-aws-vpc takes 1.7 where it took 5.8, with the same findings.
- A Terraform plan, a CloudFormation template and a Kubernetes manifest are read from disk once, so a file that changes between two reads can no longer misalign line numbers.
- **A variable default that switches a resource off no longer hides a missing companion.**
  `aws_flow_log` with `count = var.enable ? 1 : 0` and `default = false` was kept as present, so `VPC_NO_FLOW_LOGS` never fired; terraform-aws-vpc now reports it for 10 VPCs.
  A count of 0 or an empty `for_each` drops the resource wherever the value comes from.
  In a followed module the default is the value and the drop gets an info note.
  In the module you scan itself, a value from `-var`, `-var-file` or `TF_VAR_*` could replace the default, so the drop also produces one `hcl.default_disabled` warning per module and `--strict` fails on it; a value in `terraform.tfvars` or `*.auto.tfvars` settles the question.
  A default that enables the resource keeps it and flags `count_from_default` in its meta.
- **A Helm chart with an unvendored library dependency says why its workloads are missing.**
  A Bitnami chart lists the `common` library chart as a dependency and a fresh checkout has no `charts/common`, so every `include "common.names.fullname"` rendered invalid YAML and the scan ended with "Verdict: no findings".
  The gap now names the includes that no chart defines and says "dependency common is not vendored in charts/", with `helm dependency build` or installing helm as the fix, and the parse is marked `incomplete`.
  A dependency present in `charts/` or turned off by its `condition` is not reported.
- **Unresolved Helm names read as words:** `kubernetes_service.unresolved-namespace.unresolved-svc`, and `unresolved-svc-1` for a second unresolved document of the template.
- A CloudFormation `AWS::WAFv2::RuleGroup` reads like the web ACL: `Rules` becomes `rule` and `VisibilityConfig` becomes the `visibility_config` block.

#### Findings and attack paths

- **One companion resource with a target the scan cannot resolve no longer silences findings across the whole scan.**
  A `SecurityGroupIngress` with `GroupId: !Ref Param`, an `aws_security_group_rule` with `security_group_id = var.x` or an encryption configuration with `bucket = var.x` turned the facts of every possible parent Unknown, so `SG_UNRESTRICTED_INGRESS` and `S3_NO_ENCRYPTION` disappeared from every resource with no gap to say so.
  On `aws-cloudformation-templates` that removed every `SG_*` finding; it now reports 76 `SG_UNRESTRICTED_INGRESS` and 29 `SG_WEB_PORT_OPEN_TO_WORLD`.
  A world-open rule the scan can read still fires next to an unresolved rule resource, an unresolved companion makes facts Unknown only for the parents of its own input, and a `Ref` or `Fn::GetAtt` that names a parameter or an `Fn::ImportValue` can only name something outside its template, so it records no gap.
  Each remaining case is a warning-level coverage gap, `enrich.unresolved_companion`, printed on stderr even with `--quiet`, listed in the report and counted by `--strict`.
- **A CloudFormation `Ref` to a logical id of the same template now joins its resource.**
  A standalone `AWS::EC2::SecurityGroupIngress` that pointed at a security group of its own template never joined it.
  References resolve inside their own input, and the same unresolved expression on a parent and a companion links them in one input and one module.
- **`SECRET_PRIVATE_KEY` needs a whole key.**
  The rule matched the header alone, so a comment that names it was a critical finding: 111 of the secret findings across the Bitnami charts, and `threatcode scan bitnami/nginx` exited 1.
  It now matches a header, a base64 body of at least 43 characters and a footer, in YAML literals, JSON strings, heredocs, one-line forms and encrypted or PGP blocks, and reports the line of the header.
  A commented-out complete key is still a key.
- **A shell variable or template code is no longer a hardcoded secret.**
  A generic value made of shell expansions (`"$MONGODB_ROOT_PASSWORD"`) is where a secret is read from, and a generic match inside a Helm `{{ }}` action is template code.
  A bcrypt hash, a literal next to an expansion and a literal outside any action are still reported.
- **Kubernetes objects are no longer linked across alternate copies of an application.**
  A repository with raw manifests, a Kustomize base, a rendered release and a Helm chart defines the same Service and Deployment four times, and `microservices-demo` showed 16 `frontend-external` boundary findings where 4 exist.
  Two inputs that define the same kind, namespace and name are alternates and nothing links across them; a name resolves to the copy in its own input, else to a single copy in a non-alternate input.
- **An attack path through CloudFront to a bucket read with an access control is no longer raised.**
  A bucket read through `origin_access_control_id` or an origin access identity is reached only by the distribution, so the edge, the high boundary finding on it and the severity raise it caused are gone.
  A bucket that is also public keeps its own `internet -> bucket` edge, and an origin with no access control is still an edge.
- **A `*` resource in an IAM statement reaches the nodes of the role's own input only,** where it reached every bucket of the other 400 templates of a repository.
  An ARN with a literal part (`arn:aws:s3:::acme-logs-*`) still names its targets in any input.
- **The last hop of an attack path is enabled only by a finding that gives access to the store.**
  `S3_NO_ENCRYPTION` (low) was named as what made a route to a bucket an attack path and `RDS_NO_ENCRYPTION` raised a path to a database by two levels.
  An exposure, a credential in the code, a scanner finding and a weakness of authentication or privilege still enable it, and the hops before the target are unchanged.
- **The attack path rationale shows the severity the report lists:** `(low, raised to medium)` when context changed it, where it said `(medium)` for a finding the report lists as low.
- **A companion's value is no longer erased by the computed marker of the inline setting.**
  A real plan prints the deprecated inline settings of an `aws_s3_bucket` as unknown, which beat the companion in the merge, so a bucket with an AES256, suspended-versioning or public-read-ACL resource never reported `S3_NO_ENCRYPTION`, `S3_NO_VERSIONING` or `S3_PUBLIC_ACCESS`.
  The companion's value stands, queue, topic and key policies follow the same rule, and an empty `logging` list is no longer read as logging enabled.

#### Reports and the command line

- **The header names what was scanned in every format:** `ThreatCode scan of examples/aws-webapp` rather than `.`, in the JSON `input_file`, the Markdown `Input` line, the SVG title, the Navigator description and the error of an empty directory.
- **The README and the getting-started page ran the first command only from a clone.**
  `examples/` is not in the pip package, so `threatcode scan examples/aws-webapp` failed after the documented install; both pages now clone the repository first, and a test fails when the first demo scan comes before the clone.
- **Six pages described attack paths as outside suppressions and baselines,** which stopped being true; they now describe what `--write-baseline`, `--baseline` and `.threatcodeignore` do with paths, and a test baselines the demo stack and checks the exit code both ways.
- **The generated options table listed `--version` twice,** and a test fails when any option table repeats an option.
- **The `allow_local_network` error names all three allowed providers.**
- **The pre-commit example pinned `v0.9.1`, a release that predates the hook;** it and the CI page say `main` until the first release of this line is tagged.
- **`--fail-on none -f bitbucket` is reported PASSED,** and the duplicate-id warning of `threatcode.scan()` also runs on the command line.

#### Build, packaging and tests

- **`make lint` and CI checked only `src/` and `tests/`;** both run `ruff check .` and `ruff format --check .` now.
- **`make clean` left `src/threatcode.egg-info` behind.**
- **The source distribution could not run its tests.**
  A new `MANIFEST.in` ships the tests with their fixtures and the documentation, examples and scripts they read, and the CI package job checks the archive; the suite expects a git checkout, so run `git init` in an unpacked sdist first.
- **`tomli` is a development dependency;** the package never reads TOML, but it was installed for every Python 3.10 user.
- **`scripts/check_golden_scope.py` called a deleted recording out of scope** when its globs were given unquoted, because the shell expanded them; its help and `CONTRIBUTING.md` say to quote them.
- **Fixture paths in tests no longer depend on the working directory** (the Dockerfile parser and rule tests, and the Kubernetes parser tests).
- **A permanently skipped test is gone,** and a test fails if an `expected.yml` entry is marked pending.

### Security

- **The image scanner was removed,** which closes a host file deletion through layer whiteouts and symlink chains.
- **A scanned repository cannot widen its own trust:** an auto-discovered config can no longer set `fail_on`, load rules, redirect the model client, weaken redaction or raise the graph limits, and the CI notice recommends keeping the ignore file outside the tree.
- **The model request is pseudonymous, allowlisted and redacted.**
  Resources are opaque handles, every property outside a per-type allowlist is dropped, keys are matched by substring and values by secret shape, `redaction.fields` now works, redaction fails closed past 10000 values, and the `hash` strategy is a keyed HMAC.
  `--dry-run` prints the exact request without opening a connection, and a request over the limit is refused, never cut.
- **The model's reply is validated item by item,** cleaned of links, code blocks and shell runs, attributed to a resource of the scan or quarantined, and kept out of the gate.
- **Model clients refuse a redirect to another scheme, host or port,** so a key and a request are never forwarded, and retry only on 429 and 5xx with a bound.
- **Secret previews never contain secret characters:** a preview is `[REDACTED <rule id> len=<n>]`, ids and fingerprints never derive from the value, MCP secrets are stored as labels only and redacted in place in launch arguments, and scanner secrets are never copied.
- **Files are read only through discovery,** the secret scanner opens them with `O_NOFOLLOW` and checks them with `fstat`, and the walker never follows a symlink out of the tree or opens a pipe.
- **Evaluation of Terraform, CloudFormation and Helm input is bounded** in string size, collection size, nesting, expansion and total work, and the Helm fallback is a linear evaluator that took quadratic time and 14 seconds on 80 KB of unterminated actions before.
- **Output cannot inject:** Markdown, Mermaid labels, SVG ids and SARIF URIs are escaped for where they are shown.
- **The GitHub Action** passes inputs through the environment, never through `${{ }}` in a script, shows stderr between `::stop-commands::` markers, and validates the `version` input.
- **The dry-run payload contains no AWS account id or region.**
  The secret rules ran before the ARN pattern and matched the resource part of a Secrets Manager or SSM ARN, which left `arn:aws:secretsmanager:us-east-1:111122223333:secret:REDACTED_secret_2` in the request.
  An ARN is now replaced whole before the secret rules run, and a test scans the payload for any 12 digit account id.
- **Names from the scanned input are printed as visible escapes (`\x1b`), never as terminal control sequences,** in the path, verdict and coverage lines as in the table, and a test drives the whole report and stderr with an escape and a bell in a server key, a file name and an attack path.

### Internal

- **Golden recordings that changed, and why.**
  `real_shapes/helm/platform` loses `K8S_RBAC_SECRETS_READ` on a Role whose only rule lists its Secrets in `resourceNames`.
  The four http MCP recordings (`mcp/clients/mcp_config.json`, `mcp/gemini/settings.json`, `mcp/vulnerable/.mcp.json` and `real_shapes/mcp/desktop/claude_desktop_config.json`) move one boundary threat from spoofing to information disclosure, because the finding is about cleartext transport and not a missing credential; severity stays high.
  `realistic/10_aws_gaming_backend.json` loses the edge from the CDN to the `game_assets` bucket, the critical attack path through it and the boundary finding on the edge, because the distribution reads the bucket through an origin access identity.
  In `realistic/01_aws_ecommerce_platform.json` the two attack paths to the `sessions` database go from critical to high, because `RDS_NO_ENCRYPTION` no longer enables the last hop and the worst enabler is `EC2_IMDSV1` (medium, raised to high).
  No other recording moved: formatter, command line, line number, title and enabler changes are checked by their own tests.
- `enrich.unresolved_companion` is a new diagnostic code at warning level.
  `InfraGraph.node_units` maps each node id to the label of the input it came from, `CompanionSpec.additive` marks a companion whose keys are lists it can only add to, and `EnrichContext` gains `peers`, `supplied` and `expression_hits`.
- `SecretRule` has `multiline` and `verify`, `SecretScanner.scan_text` takes `templated`, and `BOUNDARY_TECHNIQUES` and `BOUNDARY_TACTICS` are removed from `threatcode.engine.mitre`.
- `Rule.properties_read` and `loader.condition_properties` return the top-level properties a rule condition reads, and the Kubernetes parser records `meta['lines']` for each object, a map from those properties to the line of the manifest key they come from.
- `ThreatReport.duplicate_ids()` returns the ids that more than one threat carries, and `threatcode.scan()` and `analyze()` log a warning when it is not empty.
- `formatters/terminal_layout.py` (wrapping primitives, `columns()`, `wrap_path()` and the `TIE` that joins two words across a wrap), `formatters/terminal_coverage.py` (what to list of gaps and errors), `formatters/terminal_table.py` (the findings table) and `formatters/terminal_verdict.py` (the Helm-aware verdict) are pure and tested with hypothesis properties: no line is wider than the width and no character is lost.
  `formatters/_utils.py` gains `verdict_items`, `rule_label`, `set_aside_phrase` and `join_words`, and a verdict is built from fixed words, so a target kind or a zone the tables do not know is never echoed.
- `formatters/diagram_labels.py` is the one place that says an edge in words, shortens an address and lists the findings that enable each hop, for the diagram, the Mermaid charts and the Markdown report.
  `ordered_attack_paths` there is the one order that numbers attack paths, and the terminal report and SARIF sort with the same key.
  The diagram's `NODE_W` is 176 (it was 160).
- `tests/test_meta.py` fails the build when `__version__` is a number that `CHANGELOG.md` already released while it still has unreleased changes, when a test opens `Path("tests/...")` relative to the working directory, and when a function, method or class in `src` is never referenced; the last two keep a list of known offenders, so a new one fails and a fixed one has to leave the list.
- The engine tests re-raise an exception from a built-in rule instead of recording it in `rule_errors`, and the graph and recording tests render Helm charts with the built-in renderer whether or not `helm` is installed.
- The generated blocks in `README.md`, `docs/getting-started.md` and the example READMEs embed the text report, the Navigator sample in `docs/mitre-attack.md` and the format list in `docs/cicd.md` come from the code, and `python scripts/gen_docs_counts.py --write` regenerates them.
- `python-hcl2` stays `>=4.3,<9`: the 4.x reading is compensated in the adapter and CI tests both ends.

### Known limitations

- Azure and GCP resources have rule findings but no topology, exposure or attack paths.
- The report does not yet list which ignore entries were applied; matched, unmatched and expired entries reach stderr as notices.
- Terraform modules from a registry or Git are not downloaded; they are reported as coverage gaps.
- CloudFormation nested stacks and transforms other than SAM are not expanded.
- The package is not on PyPI; install from the Git URL until the release checklist in `docs/releasing.md` is done.

## [0.9.1] - 2026-10-03

### Added
- **MCP client config parser** (`parsers/mcp_config.py`): turns each server in an MCP client config into an `mcp_server` resource, offline, without starting or contacting the server. Supports the `mcpServers` shape (Claude Desktop `claude_desktop_config.json`, Claude Code `.mcp.json` and `~/.claude.json` including per-project entries, Cursor `.cursor/mcp.json`, Windsurf/Devin `mcp_config.json` with `serverUrl`, the VS Code and Copilot portable `.mcp.json` and `mcp-config.json`) and VS Code's `servers` shape in `.vscode/mcp.json`, including JSONC comments and trailing commas. File names and shapes were checked against each client's documentation on 2026-10-01. Only the names of environment variables and headers are stored, never their values.
- **7 MCP rules** (`engine/rules/builtin/mcp/servers.yml`): `MCP_SECRET_IN_CONFIG`, `MCP_PLAINTEXT_TRANSPORT`, `MCP_REMOTE_NO_AUTH`, `MCP_UNPINNED_PACKAGE`, `MCP_BROAD_FILESYSTEM`, `MCP_SHELL_EXEC`, `MCP_CONTAINER_PRIVILEGED`. Each carries a STRIDE category, ATT&CK techniques, and IDs from the OWASP MCP Top 10 (2025, beta) and the OWASP Top 10 for Agentic Applications 2026 under `metadata.owasp`. Vulnerable and fixed fixtures for every client shape live in `tests/fixtures/mcp/`.
- **`threatcode fs` finds `.cursor/mcp.json` and `.vscode/mcp.json`**, which the walk previously skipped with every other dot-directory, so agent configs are scanned in the same run as the IaC.
- **SARIF tags for OWASP IDs**: rules that declare `metadata.owasp` emit `owasp-mcp-top-10/<id>` and `owasp-agentic-top-10/<id>` tags.
- ATT&CK techniques T1059 (Command and Scripting Interpreter) and T1005 (Data from Local System) added to the technique database.
- **`LICENSE`** file with the MIT license text. `pyproject.toml` already declared MIT, but the repository had no license file, so GitHub detected no license and the wheel shipped none.
- **CI `package` job**: builds the sdist and wheel, installs the wheel into a clean virtualenv, and scans `tests/fixtures/kubernetes` from outside the checkout. It fails if the wheel holds fewer than 50 rule files, loads fewer than 220 rules, or finds no threats (`scripts/smoke_test_wheel.sh`).
- **Publish workflow** (`.github/workflows/publish.yml`): publishes to PyPI with trusted publishing when a GitHub release is published, after checking that the release tag matches the package version and re-running the wheel smoke test.

### Changed
- Remote MCP servers that are not on loopback are placed in the internet trust zone.
- **README** now leads with the STRIDE and ATT&CK threat-model output and explains how ThreatCode relates to Trivy and Checkov. Corrected stale or false claims: rule counts (131 to 221), ATT&CK coverage (24 techniques in 12 tactics), supported ecosystems, a STRIDE-to-tactic table the code never applied, a GitLab example that labeled SARIF as a GitLab SAST report, and an Ollama example that the SSRF guard rejected (restored with the opt-in it needs, see Fixed).
- Package author set to Aaron Lindahl.
- `OpenAICompatibleLLMClient`'s `allow_insecure` parameter is now `allow_local_network`. Plain HTTP is no longer accepted for public addresses. The plain-HTTP warning now fires only when an API key would be sent.
- Build requirement raised to `setuptools>=77`, the first release that supports the PEP 639 `license` and `license-files` fields.

### Fixed
- **Diagram findings table**: cell text was truncated by character count while columns have fixed pixel widths, so descriptions ran into the ATT&CK column. Text is now truncated to each column's width, the severity column shows the full word instead of `MEDI`/`CRIT`, and the header separates the threat count from the timestamp.
- **Diagram edge routing**: edges were drawn straight from the bottom center of one node to the top center of the next, so same-row and upward edges cut through unrelated nodes, and trust-boundary labels on edges that skipped a lane were painted over by node boxes. Edges now follow an orthogonal router (`formatters/diagram_routing.py`) that uses only the gaps between grid rows and columns, parallel edges share one path and label, and labels are placed with a collision check above the nodes.
- **Wheel shipped without rules**: the 0.9.0 build left out all 50 builtin rule YAML files, so a pip-installed ThreatCode loaded no rules and reported no threats. `[tool.setuptools.package-data]` now includes `engine/rules/builtin/**/*.yml`.
- **mypy**: resolved a `no-any-return` error in `engine/vulns/os_advisories.py` that failed the CI typecheck job.
- **Ollama and local model servers**: the `ollama` and `local` providers could not reach a model server, because the SSRF guard on `base_url` accepted only HTTPS URLs on public addresses. `threatcode scan` crashed with a traceback whose message claimed http was allowed. The new `llm.allow_local_network: true` option lets these two providers use plain HTTP to loopback, private and shared (`100.64.0.0/10`) addresses. The `openai` and `anthropic` providers reject the option, redirects still get the strict check, link-local addresses such as `169.254.169.254` stay blocked, and the option is read only from a `--config` file.
- **Doubled `/v1` in LLM URLs**: the OpenAI-compatible client appended `/v1/chat/completions` to `base_url`, so the documented `https://api.openai.com/v1` posted to `/v1/v1/chat/completions`. `base_url` now works with or without the trailing `/v1`.
- **CLI errors**: an invalid LLM setup, a missing `--config` file or an invalid config value now prints one `Error:` line and exits 1 instead of a traceback. Config validation errors name the field without the pydantic boilerplate. When a local model server is down, the scan logs one warning line instead of a traceback and returns the rule-based findings.

## [0.9.0] - 2026-03-08

### Added

#### Expanded Misconfig Rules (131 → 221)
- **AWS** (+30 rules, 7 files): WAF web ACL (5), Secrets Manager (4), GuardDuty (4), AWS Config (4), SSM Parameter Store (4), WAFv2 rule groups (5), EKS node groups (4)
- **Azure** (+25 rules, 6 files): Key Vault (5), App Service (5), Functions (4), SQL Database (4), Cosmos DB (4), Monitor (3)
- **GCP** (+20 rules, 5 files): Cloud SQL (5), Cloud Functions (4), BigQuery (4), Pub/Sub (3), Cloud Run (4)
- **Kubernetes** (+10 rules): Pod Security Admission, default service accounts, security context defaults, seccomp profiles, resource quotas, PodDisruptionBudget, ephemeral storage, egress policies, Ingress TLS
- **Docker** (+5 rules): COPY --chown, ADD from URL, apt cleanup, digest pinning, minimal base images

#### OS Advisory Sources (2 → 5 families)
- **Ubuntu OVAL** - advisories for 18.04 (Bionic), 20.04 (Focal), 22.04 (Jammy), 24.04 (Noble) via OVAL XML
- **Amazon Linux ALAS** - advisories for AL2 and AL2023 via ALAS RSS feeds
- **RHEL CVE API** - advisories for RHEL 8 and 9 via Red Hat Security Data API with exponential backoff

#### New Lockfile Parsers (10 → 13 formats)
- **`mix.lock`** (Elixir/Hex) - regex-based parser for Hex dependencies
- **`pubspec.lock`** (Dart/Pub) - YAML-based parser for Pub dependencies
- **`conan.lock`** (C++/Conan) - JSON-based parser for Conan v2 lockfiles
- Added `Hex` and `Pub` ecosystems to OSV database update

#### Helm Chart Scanning
- **`HelmParser`** - renders Helm charts to Kubernetes YAML via `helm template` CLI or raw template fallback
- **Parser registry** - Helm chart detection via `Chart.yaml` at priority 8
- **Filesystem scanner** - automatic Helm chart discovery and misconfig scanning
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
- **`threatcode fs <path>`** - Filesystem scanner command. Walks a directory tree, discovers lockfiles, IaC files (Terraform, CloudFormation, Dockerfile, Kubernetes), and runs vuln, secret, misconfig, and license scanners against discovered files.
- **`threatcode repo <url>`** - Repository scanner command. Shallow-clones a Git repo (HTTPS/SSH) into a temp directory and runs the filesystem scanner. Supports `--branch` flag.
- **`.threatcodeignore` support** - Suppress findings by CVE ID, rule ID, or secret rule ID. Optional `exp:YYYY-MM-DD` expiration dates. Loaded automatically from the scan directory or via `--ignorefile` flag.
- **`scan_filesystem()` public API** - Programmatic filesystem scanning with ignore support.
- **`scan_repository()` public API** - Programmatic repository scanning.
- **`threatcode.ignore` module** - Parser for `.threatcodeignore` files with expiration date support.
- **`threatcode.scanner.fs` module** - Core filesystem walking and multi-scanner orchestration.
- **`threatcode.scanner.repo` module** - Git clone + filesystem scan delegation.

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
- **Image reference parser**: Full Docker reference grammar - bare names, user/repo, custom registries, digest pins, multi-component paths (e.g. `gcr.io/project/repo/img:tag`)
- **Registry client**: Docker Registry HTTP API V2 with bearer token auth, credential store (`~/.docker/config.json`), manifest list platform selection, SHA-256 digest verification; supports Docker Hub, GHCR, GCR, ECR, ACR, and any OCI-compliant registry
- **Layer extractor**: Downloads and merges OCI image layers with correct whiteout semantics (`.wh.` regular and `.wh..wh..opq` opaque whiteouts); path traversal protection; 2 GB/layer and 10 GB/image size limits
- **OS detection**: Reads `/etc/os-release`, `/etc/alpine-release`, `/etc/debian_version`, `/etc/redhat-release`, `/etc/lsb-release` - detects Alpine, Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux, Amazon Linux, Fedora, SUSE, Arch, Wolfi, Chainguard, and more
- **OS package parsers**: APK (`/lib/apk/db/installed`), DPKG (`/var/lib/dpkg/status` + `/var/lib/dpkg/status.d/*` for distroless), RPM (SQLite `rpmdb.sqlite` + BerkeleyDB Hash `Packages` with full binary header parser)
- **OS vulnerability database**: Extended `VulnDB` with `os_vulnerabilities` table; `OSAdvisoryDownloader` fetches Alpine SecDB and Debian Security Tracker data; `threatcode db update --os` downloads OS advisory data
- **Application dependency detection in images**: Finds and parses lockfiles inside images (all 10 formats); also scans Python `site-packages` METADATA for pip-installed packages
- **Image configuration checks**: `IMG_ROOT_USER`, `IMG_NO_HEALTHCHECK`, `IMG_SECRET_IN_ENV`, `IMG_PRIVILEGED_PORT`, `IMG_NO_MAINTAINER` - checks OCI image config for security best-practice violations
- **`threatcode image` CLI command**: `--format` (json/sarif/table), `--severity`, `--ignore-unfixed`, `--platform`, `--scanners vuln,secret,misconfig`, `--insecure`; table output matches standard security scanner format
- **`scan_image()` public API**: Pull and scan any image reference, returns structured dict with OS info, vulnerabilities, secrets, misconfigs

### Changed
- `VulnDB` schema extended with `os_vulnerabilities` table (backward-compatible; existing databases auto-migrate on next `init_db()`)
- `threatcode db update` gains `--os` flag to also download OS advisory data
- Version bumped to 0.7.0

## [0.6.0] - 2026-03-04

### Added

#### Multi-Scanner Architecture
- **Unified finding model**: New `FindingType` enum and `SecretFinding`, `VulnerabilityFinding`, `LicenseFinding` dataclasses in `models/finding.py` - extensible foundation for non-STRIDE findings alongside existing threat model
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
- **Lockfile parser**: 10 lockfile formats - `package-lock.json` (v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`
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
- **Expanded threat table**: Two new columns - "Description" (truncated to 60 chars, full in tooltip) and "ATT&CK Technique" (MITRE technique ID + name from `TECHNIQUE_DB`)
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
- **Edge tooltips**: All edges now have tooltips - boundary crossings explain the trust boundary, others show the edge type and endpoints
- **Boundary edge labels**: Trust boundary crossing edges display a `ZONE -> ZONE` label at their midpoint with a contrasting background
- **Summary bar**: Severity breakdown bar below the header with color-coded pills showing threat counts per severity and total STRIDE category count
- **Threat detail table**: Full SVG table below the diagram listing every threat sorted by severity, showing resource, title, STRIDE category, and source with alternating row backgrounds
- **CSS hover interactivity**: `<style>` block with hover effects for nodes (thicker stroke), edges (wider stroke), and threat table rows
- **3-column legend**: Overhauled legend with mini SVG shapes (rounded rect, cylinder, diamond, double-rect), actual line samples for each edge type, and severity badge explanations

### Changed
- **Node labels**: Top line now shows full resource type (e.g., `aws_s3_bucket`), center shows short name (e.g., `data`) in bold - replaces cryptic category-only label
- **Node width**: Widened from 130px to 160px to fit longer resource type labels
- **Legend height**: Expanded from 56px to 140px for proper 3-column layout with real shapes
- **Layout computation**: Canvas height now accounts for summary bar, threat table, and expanded legend
- **Edge rendering**: Edges wrapped in `<g class="edge-group">` groups for proper tooltip targeting
- **Legend content**: Replaced Unicode box-drawing characters with actual SVG shape primitives
- 39 diagram tests (up from 12) covering tooltips, edge labels, summary bar, threat table, legend shapes, CSS styles, and sort ordering

## [0.4.3] - 2026-03-02

### Security
- **Action command injection**: Composite action (`action.yml`) now uses environment variables instead of direct `${{ inputs.* }}` interpolation in shell - prevents shell injection via crafted input values
- **Action SHA pinning**: Pinned `setup-python` and `codeql-action/upload-sarif` to SHA hashes in composite action
- **SSRF 0.0.0.0 blocking**: `_validate_base_url()` now checks `is_unspecified` - blocks the unspecified address (`0.0.0.0`)
- **SSRF port fallback**: DNS resolution uses port 80 for `http://` URLs (was incorrectly defaulting to 443)
- **Response size limit**: OpenAI-compatible client caps response body at 10 MB to prevent memory exhaustion
- **Bidi character stripping**: `_sanitize_for_prompt()` removes Unicode bidirectional override characters (U+200E–U+202E, U+2066–U+2069)
- **Redactor prefix collision**: `unredact_string()` replaces longest placeholders first to prevent partial-match corruption
- **Redactor sensitive value recursion**: Nested dicts/lists under sensitive keys now fully redacted (previously only top-level dict values were replaced)

### Fixed
- **LLM failure resilience**: `LLMError` from LLM analysis no longer propagates - rule-based results are preserved with a logged warning
- **Edge dedup ordering**: Edge dedup key is now committed only after confirming the edge passes the limit check
- **Confidence type guard**: `Threat.confidence` validates type before clamping - non-numeric values default to 1.0
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
- **Public API DRY**: Extracted shared `_run_pipeline()` helper - `scan()` and `analyze()` no longer duplicate 90% of their code
- **Parser truthiness bug**: `parsed_data or content` replaced with `parsed_data if parsed_data is not None` - empty dicts no longer skipped
- **Swallowed exceptions**: Parser registry now logs `DEBUG` messages when parsers fail instead of silently swallowing
- **SARIF ruleIndex**: Each result now references the correct `ruleIndex` instead of hardcoded `0` - fixes GitHub Code Scanning misattribution
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
- CI `pip-audit --strict` failing because local editable package not found on PyPI - added `--skip-editable`

## [0.4.0] - 2026-03-02

### Security
- **SSRF protection rewrite**: `_validate_base_url()` now resolves hostnames via DNS and validates ALL resolved IPs using the `ipaddress` module - blocks loopback, private, link-local, reserved, and IPv4-mapped IPv6 addresses (A10-01..04)
- **Safe redirect handler**: OpenAI-compatible client uses `_SafeRedirectHandler` that re-validates redirect targets against SSRF checks
- **HTTP key warning**: Warns when API key is sent over plain HTTP (A07-01)
- **Config auto-discovery hardening**: Auto-discovered configs restricted to safe fields only (`min_severity`, `output_format`, `no_llm`, `dry_run`, `redaction`); security-sensitive fields stripped with warning (A01-01)
- **API key in config warning**: Warns to stderr when `api_key` found in config file - recommends environment variable (A02-01)
- **CI config skip**: Home directory config search skipped when `CI` env var is set (A07-02)
- **Prompt injection hardening**: Rule IDs sanitized before prompt inclusion; graph data wrapped in XML-style delimiters; system prompt reduced architecture exposure (LLM01-01, LLM01-02, LLM07-01)
- **Redaction improvements**: Added `name`, `module`, `provider`, `source_location` to sensitive keys; capped mapping at 10,000 entries; improved AWS account ID regex to require context (LLM02-01, LLM02-02, LLM10-07)
- **MITRE validation**: LLM technique/tactic IDs validated against known databases, not just prefix format; rule loader also validates against TECHNIQUE_DB (LLM05-03, LLM09-01)
- **LLM resource validation**: Resource addresses from LLM output validated against graph - unknown addresses capped at 0.5 confidence (LLM09-02)
- **Structured security logging**: Analysis pipeline logs start/completion with resource count, rule count, LLM status (A09-01)
- **Rule loader**: Blocks symlinks in extra rule paths; rejects rule files over 1 MB; logs SHA-256 checksums of built-in rules (A01-03, A04-03, A08-01, LLM04-03)
- **Graph limits**: MAX_NODES=10,000 (raises error), MAX_EDGES=50,000 (warns and skips) (LLM10-05, LLM10-06)
- **CLI hardening**: Validates output path is not a directory; creates parent dirs; sanitizes filesystem paths in errors (A01-04, A05-01)
- **Formatter sanitization**: Markdown/diff formatters escape `< > [ ] ( )` in LLM-sourced fields; SARIF formatter strips non-URI characters from resource addresses (LLM05-01, LLM05-02)
- **DryRun logging**: Removed prompt content from DEBUG logs entirely - only lengths logged (A02-02, A09-02)
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
- **`analyze()` public API**: New function returning `AnalysisResult` with both the infrastructure graph and threat report - enables diagram rendering and topology analysis from the library API
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
- **IR edge inference optimized**: Type-indexed lookups replace O(n²) nested loops in containment and IAM inference - now O(n) per resource
- **Pre-sorted prefix matching**: `categorize_resource()` and `infer_trust_zone()` use pre-sorted prefix lists built at module load instead of sorting on every call
- **IAM role matching improved**: Address-based match (`aws_iam_role.{name}`) tried first, falling back to name-based match - reduces false positives
- **Containment inference generified**: Registry-driven hints support `vpc_id→aws_vpc`, `vnet_id→azurerm_virtual_network`, `network_id→google_compute_network` out of the box, extensible via `register_containment_hint()`
- **Parser detection refactored**: Hardcoded if-elif chain replaced with priority-sorted registry - fully backward compatible
- **Validation constants consolidated**: STRIDE categories and severity levels defined once in `threatcode.constants`, imported by `models/threat.py`, `engine/llm/parser.py`, and `engine/rules/loader.py`

### Removed
- **Dead code**: `ir/boundaries.py` (78 lines, never imported) - boundary analysis was already implemented in `engine/hybrid.py` and `ir/graph.py`

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
- **SSRF protection**: OpenAI-compatible LLM client validates `base_url` - blocks internal/loopback/private IP ranges and cloud metadata endpoints (169.254.169.254)
- **Recursion depth limits**: Rule matcher (max 10), Terraform module walker (max 50), and redactor (max 50) now cap recursion depth to prevent stack overflow from malicious inputs
- **DryRunLLMClient no longer leaks prompt content** to stderr - only shows metadata (lengths); full content available at DEBUG log level only
- **stride_category validation**: Threat dataclass validates STRIDE category values on construction, defaults unknown values to `information_disclosure`
- **Expanded redaction**: Added 11 sensitive field names (secret, password, token, api_key, access_key, secret_key, connection_string, credentials, private_key, certificate)
- **Config auto-discovery warning**: Logs warning when auto-discovered `.threatcode.yml` sets `llm.base_url`, recommending `--config` flag in CI
- **Path traversal protection**: `extra_rule_paths` resolved to absolute paths and validated before loading
- **Rule ID uniqueness**: Enforced across all loaded rules - duplicates now raise `RuleLoadError`
- **MITRE ID validation**: Rule loader validates technique IDs match `T####(.###)?` and tactic IDs match `TA####`
- **Anthropic client empty response guard**: Checks for empty `message.content` before indexing

## [0.2.0] - 2026-02-28

### Added
- MITRE ATT&CK Cloud Matrix integration - all 19 rules mapped to ATT&CK technique IDs
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
- EC2_NO_MONITORING rule condition had broken `any_of` nesting - never fired
- EC2_UNENCRYPTED_EBS rule condition had broken `any_of` nesting - never fired
- RDS_NO_ENCRYPTION rule condition had broken `any_of` nesting - never fired

### Removed
- `jinja2` dependency (listed but never imported)

### Security
- Code audit: no eval(), exec(), pickle, marshal, __import__, or compile() in codebase
- All YAML loading uses yaml.safe_load() exclusively
- No string interpolation of user input into shell commands
- LLM responses parsed as JSON only, never executed
- Regex patterns reviewed for ReDoS - all linear, no nested quantifiers
- Prompt injection guard added to LLM system prompt
- Added `pip-audit` to dev dependencies for vulnerability scanning

## [0.1.1] - 2026-02-28

### Changed
- Rewrite README to lead with library API - ThreatCode is a Python library first, CLI second
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
