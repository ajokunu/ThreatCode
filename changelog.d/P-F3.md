### Changed
- **A boundary title leads with what tells crossings apart.**
  `Trust boundary crossing: aws_lb.front (dmz) -> aws_instance.app[0] (private)` is now `dmz > private: to aws_instance.app[0] (tcp/8080)`, with `, unencrypted` or `, unauthenticated` when the input says so.
  The RESOURCE column already shows `aws_lb.front`, and the old title put the part that differs last, so two crossings from one resource read alike in any report that cuts a title.
  The description no longer says `(network_flow)` or `(data_flow)`: it says `data flow` and `network flow`, or nothing.
- **Rule texts name no internal property.**
  `K8S_PRIVILEGED_CONTAINER` no longer sends the reader to `container_findings`, and `MCP_UNPINNED_PACKAGE` no longer sends them to `unpinned_reasons`, fields that no report shows.
  A test fails when the title, description or mitigation of a built-in rule names a property a parser writes or an edge type.
- **`K8S_RBAC_SECRETS_READ` is a definitive finding.**
  The parser has honoured `resourceNames` since the RBAC rules were rewritten, so a grant that names its Secrets no longer fires and one that does not is proven, not guessed.
  The description and the mitigation no longer say that the rule cannot tell, and the finding's confidence is 1.0 instead of 0.7.
- **An MCP server with no credential in its configuration is no longer called unauthenticated by the parser.**
  The edges of the agent and its servers carry `authenticated: true` when a header, an `oauth` block or credentials in the URL show a credential, and carry no flag otherwise, because a client that follows the MCP authorization spec discovers OAuth when it connects.
  The boundary analysis reads the flag as the edge states it, and keeps the low confidence and the `low` severity of `MCP_REMOTE_NO_AUTH` for a flow whose only open question is that sign-in.
  A design input that declares such a flow unauthenticated is now believed, as any other.
- **An attack path attaches a finding to the one hop it opens.**
  The security group that admits the internet to a load balancer used to be listed under the internet hop and again under the load balancer, whose edge to its targets names the same group.
  `hops[].enabled_by` lists it once, on the first hop; the path's severity, rationale and the findings' `path_ids` are unchanged.
- **Kubernetes findings point at the key they are about.**
  `K8S_PRIVILEGED_CONTAINER` on `examples/k8s-platform/daemonset.yaml` was reported at `daemonset.yaml:1`, as was nearly every Kubernetes finding in text, JSON, SARIF and Bitbucket output.
  It is now at line 23, the `privileged: true` of the container that sets it, `K8S_HOST_NETWORK` is at 17 and `K8S_RBAC_SECRETS_READ` at 13, the rule of the Role that reads Secrets.
  A finding about something that is missing points at the object that should hold it (the `securityContext` of the first container without a seccomp profile), and a finding about the whole object, such as a missing NetworkPolicy or a trust boundary crossing, points at its `kind:` line.
  A secret keeps the line it was found on, and a manifest whose text is not available (a Helm chart rendered in memory) keeps the line of its document.
- **Every coverage gap is listed once.**
  `coverage.gaps` drops a diagnostic that repeats with the same code, file, line and message, and `coverage.errors` drops a repeated error, so a module read through several calls no longer lists each unresolved reference once per call.
  A CloudFormation template whose only entries are skipped (an `Fn::ForEach` loop) used to list `cfn.skipped_resource` and `parse.zero_resources` for the one cause; it lists the skip, which says why.
  The input error that makes such a scan exit 2 is unchanged.
- **Paths in a report are relative to the scan root, whatever they point at.**
  A Terraform module in a parent directory (`source = "../modules/net"`) used to report its findings, gaps and errors with the absolute path of the machine the scan ran on.
  It is now `../modules/net/main.tf`, so fingerprints and baselines of a scan do not change when the tree is cloned somewhere else.
- **A local module directory is in the report once.**
  `modules/vpc` is a module of its own, and `module "vpc" { source = "./modules/vpc" }` in its parent reads the same files, so scanning the repository listed every resource twice (`aws_s3_bucket.m` and `module.vpc.aws_s3_bucket.m`) with every finding.
  A directory whose every resource another module reads through a call is no longer put in the graph on its own, the report says so in a `graph.unit_superseded` note, and its files are still scanned for secrets.
  A directory the calls do not fully reach (a remote source, `count = 0`) is still scanned.
- **A finding names its resource type.**
  A secret finding used to have an empty `resource_type`; it now carries the type of the resource it exposes.
- **A rule file that names a revoked ATT&CK technique is warned about.**
  A custom rule with `T1002` in `metadata.mitre.techniques` logs that ATT&CK revoked it and which technique replaced it (and a deprecated one logs that it has no replacement), where only an unknown id was reported.
  The rule still loads.

### Internal
- `Rule.properties_read` and `loader.condition_properties` return the top-level properties a rule condition reads, in the order it names them; the pipeline uses them to find the line of a Kubernetes finding.
- The Kubernetes parser records `meta['lines']` for each object, a map from the properties a rule reads to the line of the manifest key they come from, and `_role_properties` shares its per-rule scan with the line lookup.
- The golden recordings are unchanged: they record addresses, rule ids, severities, techniques, paths, nodes and edges, and none of those moved.
  The Kubernetes lines, the boundary titles and descriptions and the hop enablers are checked by the pipeline, boundary and path tests instead.
- `tests/test_engine/test_docker_rules.py` and `tests/test_parsers/test_kubernetes.py` build their fixture paths from `Path(__file__)`, so they pass from any working directory.
- The engine tests re-raise an exception from a built-in rule instead of recording it in `rule_errors`, and the graph and recording tests render Helm charts with the built-in renderer whether or not `helm` is installed, so the recordings hold on a machine that has it.
