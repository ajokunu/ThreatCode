# Examples

Three demo stacks, each built to show a different kind of attack path.
Every command in these READMEs runs in the test suite, and the reports and path lists are generated from the code, so what you read is what you get.

| Example | What it models | Input | Paths |
|---------|----------------|-------|-------|
| [aws-webapp](aws-webapp/README.md) | A load balancer, two app instances, a database, a customer data bucket and a secret on AWS, plus a Trivy report | Terraform plan JSON and a scanner result | Internet to the data bucket, the database secret and the database |
| [k8s-platform](k8s-platform/README.md) | An Ingress, a Service, a Deployment, a ClusterRole that reads every Secret, and a privileged DaemonSet | Kubernetes manifests | Internet to a Secret, directly and through cluster RBAC |
| [agent-workstation](agent-workstation/README.md) | A coding agent with a filesystem server, a fetch server and a remote tool server | An MCP client config | Internet to the home directory, through the agent |

Run one from the root of the repository:

```bash
pip install -e .
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json
```

The scan exits 1 on all three, because each has a finding or attack path at or above the default `--fail-on high`.
Add `--fail-on none` to see the report without the exit code, and `-f json`, `-f markdown`, `-f sarif` or `-f mermaid` for other formats.

Each example has an `expected.yml` that lists the nodes, the paths and the key findings a scan must produce.
`tests/test_examples_paths.py` and `tests/test_examples_ingest.py` check them, so an example cannot silently stop showing what its README says.

These stacks are hand-built to be small and readable.
The Terraform plan is real-shape `terraform show -json` output with create-time ids unknown and relationships in configuration references, written by hand because no Terraform binary was available.
