### Fixed
- **One companion resource with a target the scan cannot resolve no longer silences findings across the whole scan.**
  A `SecurityGroupIngress` with `GroupId: !Ref Param`, an `aws_security_group_rule` with `security_group_id = var.x` or an `aws_s3_bucket_server_side_encryption_configuration` with `bucket = var.x` turned the facts of every possible parent in the scan Unknown, so `SG_UNRESTRICTED_INGRESS`, `S3_NO_ENCRYPTION` and the other findings that read them disappeared from every resource, and no coverage gap said so.
  On `aws-cloudformation-templates` that removed every `SG_*` finding (717 findings and none of them a security group rule).
  It now reports 76 `SG_UNRESTRICTED_INGRESS` and 29 `SG_WEB_PORT_OPEN_TO_WORLD`.
  Several changes make that true.
  A world-open rule that the scan can read still fires next to an unresolved rule resource, because a rule resource can only add ingress.
  An unresolved companion makes facts Unknown only for the parents of its own input (the file, template or Terraform module that wrote it), because a reference never names a resource of another input.
  Every place where that is done is a new warning-level coverage gap, `enrich.unresolved_companion`, printed on stderr even with `--quiet`, listed in the report and counted by `--strict`.
  A scan that has one now exits 2 under `--strict`, which is the intent of the gap.
  A CloudFormation `Ref` or `Fn::GetAtt` that names a parameter or an `Fn::ImportValue` can only name something outside its template, so it is no longer a possible parent and records no gap.
- **A CloudFormation `Ref` to a logical id of the same template now joins its resource.**
  Before, a `Ref` was never looked up, so a standalone `AWS::EC2::SecurityGroupIngress` that pointed at a security group of its own template never joined it, and `SG_UNRESTRICTED_INGRESS` stayed silent on the group.
  References now resolve inside their own input, so a logical id of one template never satisfies a parameter of the same name in another.
  The same unresolved expression on a parent and a companion (a `!Sub "${AppName}-data"` bucket name and the policy that points at that name) now links them in one input and one module.
- **`SECRET_PRIVATE_KEY` needs a whole key.**
  The rule matched the header `-----BEGIN RSA PRIVATE KEY-----` alone, so a comment that names the header was a critical finding.
  111 of the secret findings across the Bitnami charts were such comments, and `threatcode scan bitnami/nginx` exited 1 under the default `--fail-on high`.
  The rule now matches a header, a base64 body of at least 43 characters and a footer, in YAML literals, JSON strings with escaped line breaks, heredocs, one-line forms and encrypted or PGP blocks, and reports the line of the header.
  A commented-out complete key is still a key.
  A comment, a documentation example with the body elided and a template action inside a block are not.
- **A shell variable or template code is no longer a hardcoded secret.**
  A generic value made of shell expansions (`"$MONGODB_ROOT_PASSWORD"`, `$USER:$PASS`) is where a secret is read from, not the secret.
  A generic match inside a Helm `{{ }}` action (`{{- range $index, $secret := ... }}`) is template code and is dropped in a chart.
  A bcrypt hash, a literal next to an expansion and a literal in a template outside any action are still reported.
- **Kubernetes objects are no longer linked across alternate copies of an application.**
  A repository that holds one application as raw manifests, a Kustomize base, a rendered release and a Helm chart defines the same Service and Deployment four times, and every Service reached the Deployment of every variant: 16 `frontend-external` to `frontend` boundary findings in `microservices-demo` where 4 exist.
  Two inputs that define the same kind, namespace and name (a Namespace aside) are alternates and nothing links across them.
  A name reference resolves to the copy in its own input, else to a single copy in an input that is not an alternate.
  When two Services of one name both select a workload of a third input, neither claims it.
  A Service and a Deployment in separate files of one directory are still joined.
- **A remote MCP server with no credential no longer fails CI as unauthenticated.**
  The parser sets `authenticated` false for a server with no credential in its config, but a client that follows the MCP authorization spec discovers OAuth when it connects.
  For a flow that ends at an MCP server, that reading is now unknown.
  The boundary finding carries the confidence of an absence (0.5) and, when authentication is the only open question, at most the severity of `MCP_REMOTE_NO_AUTH` (low), so a lone `.mcp.json` over https exits 0.
  A server over plain http stays a definite high finding, now classed as information disclosure like `MCP_PLAINTEXT_TRANSPORT` instead of spoofing.
  The mitigation of the server-to-agent direction no longer asks the agent to be authenticated.
- **An attack path through CloudFront to a bucket the distribution reads with an access control is no longer raised.**
  A bucket that a distribution reads through `origin_access_control_id` or an origin access identity is not reached from the internet by that edge: only the distribution can read it, and what it serves from it is the content it exists to publish.
  The edge is no longer added, so the path, the high boundary finding on the edge and the severity raise it caused on unrelated findings of the bucket are gone.
  A bucket that is also open to everyone has its own `internet -> bucket` edge, and an origin with no access control is still an edge.
- **A `*` resource in an IAM statement reaches the nodes of the role's own input only.**
  Once the security groups of a multi-template repository stopped being silenced, the internet reached load balancers whose role has a `*` resource, and that reached every bucket of the other 400 templates.
  An ARN or a pattern with a literal part (`arn:aws:s3:::acme-logs-*`) still names its targets in any input.
- **The last hop of an attack path is enabled only by a finding that gives access to the store.**
  Any finding on the target used to enable it, so `S3_NO_ENCRYPTION` (no customer-managed key, low) was named as what made a route to a bucket an attack path, and `RDS_NO_ENCRYPTION` raised the path to a database by two levels.
  An exposure, a credential in the code, a scanner finding and a weakness of authentication or privilege still enable it.
  Findings on the hops before the target are unchanged.
- **The attack path rationale shows the severity the report lists.**
  It said `(medium)` for a finding the report lists as low, because it named the effective severity.
  It now says `(low, raised to medium)` when context changed it.
- **A companion's value is no longer erased by the computed marker of the inline setting.**
  A real Terraform plan prints the deprecated inline settings of an `aws_s3_bucket` (`acl`, `logging`, `versioning`, `server_side_encryption_configuration`, `policy`) as unknown with no reference.
  The unknown beat the value of the companion resource in the merge, so a bucket with an AES256 encryption resource, a suspended versioning resource or a public-read ACL resource never reported `S3_NO_ENCRYPTION`, `S3_NO_VERSIONING` or `S3_PUBLIC_ACCESS` on a real plan.
  The companion's value now stands, queue, topic and key policies follow the same rule, and a bucket with no companion still has the fact unknown.
  An empty `logging` list, which a plan prints for no block, is no longer read as logging enabled.
- **The dry-run payload no longer contains an AWS account id or region.**
  The secret rules ran before the ARN pattern and matched the resource part of a Secrets Manager or SSM ARN, and the ARN was then skipped because a placeholder was already inside it.
  `scan examples/aws-webapp --dry-run` sent `arn:aws:secretsmanager:us-east-1:111122223333:secret:REDACTED_secret_2`.
  An ARN is now replaced whole before the secret rules run, and a test scans the payload for any 12 digit account id.

### Changed
- `enrich.unresolved_companion` is a new diagnostic code at warning level, so it is a coverage gap.
  A scan of a repository that has a companion resource with a target the scan cannot resolve prints it, and `--strict` exits 2 on it.
- `InfraGraph.node_units` maps each node id to the label of the input it came from, beside `node_formats`.
- `CompanionSpec.additive` marks a companion whose keys are lists it can only add to.
  The security group rule resources set it.
- `EnrichContext.peers` returns the nodes of the same input when the graph records it, `EnrichContext.supplied` names the keys a companion has given a node, and `EnrichContext.expression_hits` finds the nodes that state their name with a given expression.
- `SecretRule` has `multiline` and `verify`, and `SecretScanner.scan_text` takes `templated`.
- The `_exposure` pseudo-property in a rule condition reads the exposure the graph decided for the node (`internet`, `internal`, or unknown).
- A rule's `metadata.cwe` and `metadata.cis` are validated at load time.
  A CWE id that is not `CWE-<number>` warns, and a value that is not an id or a list of ids is refused.
- A Secrets Manager ARN written as `name-*` or `name-??????` names the secret, the way a Terraform policy writes the suffix Secrets Manager adds.
- `BOUNDARY_TECHNIQUES` and `BOUNDARY_TACTICS` are removed from `threatcode.engine.mitre`.
  The boundary phase has derived the techniques of a crossing from its zone pair since the attack path release.

### Golden recordings
- `mcp/clients/mcp_config.json`, `mcp/gemini/settings.json`, `mcp/vulnerable/.mcp.json` and `real_shapes/mcp/desktop/claude_desktop_config.json` (model): one boundary threat each changes from stride `spoofing` to `information_disclosure`.
  All four are http servers, so the finding is about the cleartext transport, which is evidence, and not about a missing credential, which is not.
  Severity stays high.
- `realistic/10_aws_gaming_backend.json` (graph and model): the edge from the CDN to the `game_assets` bucket, the critical attack path through it and the high boundary finding on the edge are gone.
  The distribution reads the bucket through an origin access identity.
  The bucket is public, so `internet -> game_assets` stays.
- `realistic/01_aws_ecommerce_platform.json` (model): the two attack paths to the `sessions` database go from critical to high.
  `RDS_NO_ENCRYPTION` (high, raised to critical by reachability) used to be the worst enabling finding, and it no longer enables the last hop.
  The worst is now `EC2_IMDSV1` on the instance (medium, raised to high).
