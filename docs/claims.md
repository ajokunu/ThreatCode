# Claims and their proof

This page lists what ThreatCode can be said to do in a demo, a talk, a blog post or a pitch, and the command or test that proves each claim.
If a claim is not here, do not make it.
The blocks on this page run in the test suite, so a claim that stops being true fails the build.

## The claims

| # | Claim | Proof |
|---|-------|-------|
| 1 | It finds attack paths from the internet to data, secrets and admin identities in infrastructure code. | [Claim 1](#claim-1) and `tests/test_examples_paths.py` |
| 2 | It reads Terraform plans and HCL, CloudFormation and SAM, Kubernetes, Helm, Dockerfiles and MCP agent configs. | `tests/test_docs.py::TestClaimsStayTrue::test_every_documented_input_round_trips_through_a_fixture` |
| 3 | Attack paths are modeled for AWS, Kubernetes and MCP configs. Azure and GCP get findings but no topology. | `tests/test_docs.py::TestClaimsStayTrue::test_azure_and_gcp_have_rule_findings_and_no_attack_paths` |
| 4 | It has 256<!-- count:rules --> built-in rules with STRIDE and ATT&CK mappings, in 6 groups. | [Rule catalog](rules.md), generated and checked by `scripts/gen_docs_counts.py --check` |
| 5 | Rules and the engine reference 36<!-- count:techniques --> ATT&CK techniques in 12<!-- count:tactics --> tactics of ATT&CK v19.2<!-- count:attack_version -->. | [MITRE ATT&CK](mitre-attack.md), generated from the code |
| 6 | It joins Trivy, Grype, OSV-Scanner and SARIF results to the graph, so a critical CVE on an exposed workload is a step in a path. | [Claim 6](#claim-6) |
| 7 | The exit code is 0 clean, 1 gate tripped, 2 the scan cannot be trusted. | [Claim 7](#claim-7) and `tests/test_pipeline.py` |
| 8 | A scan never reports a clean pass for input it did not analyse. | [Claim 8](#claim-8) |
| 9 | Terraform state is rejected, not scanned as an empty plan. | [Claim 9](#claim-9) |
| 10 | The same input gives byte-identical output. | [Claim 10](#claim-10) and `tests/test_pipeline.py::test_two_runs_with_source_date_epoch_are_byte_identical` |
| 11 | Nothing leaves the machine unless you turn on the model review, and the request can be inspected first. | [Claim 11](#claim-11) and `tests/test_docs.py::TestClaimsAreProven::test_only_the_model_client_opens_a_connection` |
| 12 | Findings from the model are advisory and never fail the gate. | `tests/test_pipeline.py::test_llm_findings_are_advisory_and_never_gate` |
| 13 | A secret finding never contains the secret. | `tests/test_engine/test_secret_scanner.py::test_every_builtin_rule_previews_without_the_secret` |
| 14 | A repository cannot turn off its own gate with a config file. | [Claim 14](#claim-14) and `tests/test_config_security.py` |
| 15 | Hostile files are scanned within a time and memory budget. | `tests/hostile/test_hostile_inputs.py` and the [security model](security-model.md) |
| 16 | On ten realistic fixtures that plant 39 issues it finds 37<!-- count:benchmark_found --> of 39<!-- count:benchmark_total --> and reports no finding on hardened resources. | [Benchmark](benchmark.md) and `tests/test_quality/test_expected.py` |
| 17 | It produces SARIF that validates against the SARIF 2.1.0 schema and that GitHub code scanning can place. | `tests/test_formatters/test_schema_conformance.py` and `tests/test_formatters/test_sarif.py` |
| 18 | The CLI has two commands, `scan` and `diff`. | [Claim 18](#claim-18) |

## Claim 1

The demo stack has three paths from the internet to the customer data bucket, the database secret and the database, and the scan exits 1.

<!-- runnable -->

```bash
status=0; threatcode scan examples/aws-webapp -f json -o report.json || status=$?
test "$status" -eq 1
python - <<'EOF'
import json
report = json.load(open("report.json"))
targets = sorted(path["target"] for path in report["attack_paths"])
assert targets == [
    "aws_db_instance.orders",
    "aws_s3_bucket.customer_data",
    "aws_secretsmanager_secret.db_credentials",
], targets
assert all(path["entry"] == "internet" for path in report["attack_paths"])
EOF
```

## Claim 6

With the Trivy report ingested, the critical CVE sits on both instances and every path becomes critical.
The CVE is also a step in the paths: in each of the three paths, the finding for the CVE is one of the findings that enable the hop through `aws_instance.app[0]`.

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp --fail-on none -f json -o baseline.json
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json --fail-on none -f json -o report.json
python - <<'EOF'
import json
report = json.load(open("report.json"))
baseline = json.load(open("baseline.json"))
# Without the ingest there is no scanner finding and not every path is critical.
assert not [t for t in baseline["threats"] if t["source"] == "scanner"]
assert [p["severity"] for p in baseline["attack_paths"]] != ["critical"] * 3
cves = [t for t in report["threats"] if t["source"] == "scanner"]
assert sorted(t["resource_address"] for t in cves) == ["aws_instance.app[0]", "aws_instance.app[1]"]
assert all(t["rule_id"] == "trivy:CVE-2022-37434" and t["severity"] == "critical" for t in cves)
assert [p["severity"] for p in report["attack_paths"]] == ["critical"] * 3
assert report["ingest"][0]["unattached"] == 0

threats = {t["id"]: t for t in report["threats"]}
for path in report["attack_paths"]:
    hops = {hop["node_id"]: hop for hop in path["hops"]}
    enablers = [threats[i] for i in hops["aws_instance.app[0]"]["enabled_by"]]
    assert any(
        t["source"] == "scanner"
        and t["rule_id"] == "trivy:CVE-2022-37434"
        and t["resource_address"] == "aws_instance.app[0]"
        for t in enablers
    ), (path["target"], [t["rule_id"] for t in enablers])
    for hop in path["hops"]:
        for finding_id in hop["enabled_by"]:
            finding = threats[finding_id]
            if finding["source"] == "scanner":
                assert finding["resource_address"] == hop["node_id"], (hop["node_id"], finding_id)
EOF
```

## Claim 7

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp --fail-on none -o /dev/null
status=0; threatcode scan examples/aws-webapp -o /dev/null || status=$?; test "$status" -eq 1
status=0; threatcode scan examples/no-such-directory -o /dev/null || status=$?; test "$status" -eq 2
```

## Claim 8

A Terraform root that only calls a registry module has nothing ThreatCode can model, so the scan exits 2 instead of reporting a clean pass.
A root that also declares a resource of its own is scanned, the module is reported as a coverage gap that names its source, and `--strict` turns the gap into exit 2.

<!-- runnable -->

```bash
cat > only_module.tf <<'EOF'
module "bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
}
EOF
status=0; threatcode scan only_module.tf -o /dev/null || status=$?; test "$status" -eq 2

cat > main.tf <<'EOF'
module "bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
}

resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}
EOF
threatcode scan main.tf --fail-on none -f json -o report.json
python -c "import json; gaps = json.load(open('report.json'))['coverage']['gaps']; assert gaps and gaps[0]['code'] == 'hcl.module_call_skipped', gaps"
status=0; threatcode scan main.tf --strict -o /dev/null || status=$?; test "$status" -eq 2
```

## Claim 9

<!-- runnable -->

```bash
echo '{"format_version": "1.0", "values": {"root_module": {}}}' > state.json
status=0; threatcode scan state.json -o /dev/null 2> err.txt || status=$?
test "$status" -eq 2
grep -q "terraform plan -out tfplan && terraform show -json tfplan" err.txt
```

## Claim 10

<!-- runnable -->

```bash
threatcode scan examples/k8s-platform --fail-on none --no-timestamp -f json -o first.json
threatcode scan examples/k8s-platform --fail-on none --no-timestamp -f json -o second.json
cmp first.json second.json
```

## Claim 11

`--dry-run` builds the request and writes it to a file without opening a connection, and without the optional model client installed.

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp --dry-run --dry-run-output request.json --fail-on none -o /dev/null
python - <<'EOF'
import json
request = json.load(open("request.json"))
text = json.dumps(request)
assert "customer_data" not in text and "tfplan.json" not in text
assert "aws_s3_bucket.n" in text
EOF
```

## Claim 14

A `.threatcode.yml` in the scanned tree that sets `fail_on: none` is ignored, with a warning.

<!-- runnable -->

```bash
mkdir proj
cp examples/aws-webapp/tfplan.json proj/
printf 'fail_on: none\n' > proj/.threatcode.yml
status=0; threatcode scan proj -o /dev/null 2> err.txt || status=$?
test "$status" -eq 1
grep -q "restricted fields" err.txt
```

## Claim 18

<!-- runnable -->

```bash
threatcode --help > help.txt
grep -q "^  scan " help.txt
grep -q "^  diff " help.txt
test "$(sed -n '/^Commands:/,/^$/p' help.txt | grep -c '^  [a-z]')" -eq 2
```
