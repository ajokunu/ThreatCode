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
  `.threatcodeignore` entries are `<ID> [resource=GLOB] [file=GLOB] [exp:YYYY-MM-DD] [reason="text"]`, where `ID` is a rule id, a finding id, a fingerprint or a CVE or GHSA alias.
  An entry without a reason, a global entry without an end date, an entry that names a removed rule and an entry that expired are warned, and a notice in CI explains that a pull request can edit an ignore file inside the scanned tree.
  `--write-baseline FILE` records every finding and `--baseline FILE` hides those findings from the gate and the listings; a baseline is not written when the scan had input errors.
- **Reproducible output.**
  `SOURCE_DATE_EPOCH` fixes the timestamp and `--no-timestamp` leaves it out.
  Findings are sorted, and every path in a report is POSIX and relative to the scan root, so the same tree gives byte-identical output wherever it is checked out.
- **One settings resolver.**
  A flag wins over `THREATCODE_FAIL_ON`, `THREATCODE_MIN_SEVERITY`, `THREATCODE_FORMAT` and `THREATCODE_LLM`, which win over the config file, which wins over the default.
  Config models reject unknown keys with a suggestion, and graph limits can be set with `--max-nodes`, `--max-edges`, `max_nodes`, `max_edges` and the `THREATCODE_MAX_*` variables.
- **A config file inside the scanned repository cannot widen its own trust.**
  An auto-discovered `.threatcode.yml` is announced on stderr and only `min_severity` and `output_format` are read from it.
  `fail_on`, `extra_rule_paths`, `llm`, `redaction` and the graph limits come only from a file named with `--config`.
- **A text report for terminals** with a verdict line, the attack paths, a table that fits the terminal width, and the coverage block.
  Group options `-v`, `-q`, `--debug`, `--no-color` and `--version` go before the command, and every help text ends with examples and the exit codes.
- **`diff` checks what it is given and lists attack paths first.**
  Both files must be `threatcode scan -f json` reports, attack paths that appeared or closed are compared by id, `-f text` and `-o` are supported, and `--fail-on-new SEVERITY` also fails on a new attack path.
- **A Python API through the same pipeline:** `scan(paths, **settings)` returns the report dict, `analyze(paths, **settings)` the graph with the report, and `run_scan(ScanRequest)` the exit code and the coverage.
  Names load on first use, so `import threatcode` stays cheap.

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
- **The core install is smaller,** the version is single-sourced from `threatcode.__version__`, the wheel ships `py.typed`, and Python 3.14 is a declared classifier.
- **The wheel smoke test compares instead of counting:** the packaged rule files must equal the checkout's and the loaded rule ids must equal the ids in the source.
- **Releases are gated on CI,** the release tag is checked against the version in the built wheel, and CI runs on every pull request with a matrix of Python 3.10 to 3.14 on Linux plus one macOS and one Windows job.
- **The GitHub Action no longer ends with `|| true`.**
  It captures the exit code, fails the job on exit 2 at once and on exit 1 after the report is written and uploaded, handles paths with spaces, and its SARIF upload is pinned to a commit that exists.
  The install wording stays at the Git URL until PyPI returns 200.
- **Provider defaults that a plan materialises** (for example an EKS cluster's public endpoint) are applied to Terraform HCL and CloudFormation input only, never to a plan or a design.
- **Loaded rules are immutable** and the built-in rules are parsed once per process.

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
- **Known limitation:** attack paths cannot be suppressed or baselined from the command line yet, so a path keeps gating until it is fixed.
  The module API for it exists in `threatcode.suppressions`.

### Known limitations

- Azure and GCP resources have rule findings but no topology, exposure or attack paths.
- A baseline hides findings, not attack paths, and `.threatcodeignore` cannot name an attack path yet.
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
