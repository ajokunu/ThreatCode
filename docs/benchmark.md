# Benchmark

How many of the issues that are planted in realistic infrastructure does ThreatCode find, and how much noise does it add?
This page publishes the number the test suite measures, so a claim about detection quality can be traced to a command.

## What is measured

The repository holds ten realistic fixtures in `tests/fixtures/realistic/`: AWS and Azure stacks written the way real teams write them, in Terraform plan JSON, HCL and CloudFormation.
They plant issues the way real code does, with a `TODO`, a ticket id, a comment such as "temporary, remove before launch" or a resource named `TempAllowAll_RemoveMe`.
For each fixture, `tests/test_quality/expected/<fixture>.yml` lists by hand:

- **`must_find`:** the planted issues, each with the resource, the rule or class of finding that counts, and a `why` that quotes the comment or attribute that plants it.
- **`must_not_find`:** hardened resources and companion resources that no finding should sit on, for example a bucket whose encryption, versioning and logging are set by sibling resources.

The harness scans each fixture with the same pipeline as `threatcode scan` (secret findings and attack-path context included, suppression files off), and scores recall (the share of `must_find` entries with a matching finding on that resource), violations (findings on a `must_not_find` resource) and companion duplicates (the same rule firing on a resource and on its companion).

The set is small and it is the product's own test data, so read the number as a regression gauge and a sanity check, not as a detection rate on code in the wild.
The planted issues are the ones the authors thought of.

## Result

<!-- gen:benchmark -->
On this build ThreatCode finds **37 of the 39** planted issues (95%) and reports **0** findings on resources that are listed as hardened.

| Fixture | Found | Recall | Violations | Findings |
| --- | --- | --- | --- | --- |
| `01_aws_ecommerce_platform.json` | 5/6 | 83% | 0 | 34 |
| `02_azure_kubernetes_cluster.tf` | 2/3 | 67% | 0 | 16 |
| `03_aws_data_pipeline.yaml` | 4/4 | 100% | 0 | 17 |
| `04_aws_java_microservices.json` | 4/4 | 100% | 0 | 20 |
| `05_hybrid_vpn_datacenter.tf` | 4/4 | 100% | 0 | 11 |
| `06_aws_serverless_api.yaml` | 2/2 | 100% | 0 | 16 |
| `07_azure_webapp_java.tf` | 2/2 | 100% | 0 | 9 |
| `08_aws_ml_training_platform.json` | 6/6 | 100% | 0 | 20 |
| `09_aws_healthcare_hipaa.yaml` | 3/3 | 100% | 0 | 9 |
| `10_aws_gaming_backend.json` | 5/5 | 100% | 0 | 33 |
| **Total** | **37/39** | **95%** | **0** | 185 |

### Issues the build does not find

- `01_aws_ecommerce_platform.json`, `aws_lambda_function.order_processor`: role is ecommerce-lambda-admin-role
  The role is an ARN of a role outside the scan and only its name says admin, and ThreatCode does not read permissions from a name.
- `02_azure_kubernetes_cluster.tf`, `azurerm_kubernetes_cluster.platform`: # RBAC is not enabled - flagged in last security review (TODO: PLAT-901 enable Azure AD RBAC)
  The cluster never sets role_based_access_control_enabled, whose azurerm default is true, and no rule covers a missing Azure AD integration block, so nothing honest can be reported.

The ratchet in `tests/test_quality/expected/ratchet.yml` is a recall of at least 94.87% with at most 0 violations and 0 companion duplicates.
<!-- /gen:benchmark -->

Run it yourself:

```bash
python -m pytest tests/test_quality -q -s
```

With `-v` (or `THREATCODE_QUALITY_DETAIL=1`) the report lists every missed issue and violation.
`THREATCODE_QUALITY_SUMMARY=<path>` writes a Markdown table for a CI step summary.

## How the number is kept honest

- **A ratchet.**
  `tests/test_quality/expected/ratchet.yml` records the measured recall and the allowed violations.
  The test fails when a scan falls below it and when the file is looser than the measurement, so the number can only be raised by finding more.
- **A miss must be explained.**
  An entry that is missed carries `known_miss: <reason>` or the test fails.
  An entry marked `known_miss` that is found fails too, so the mark cannot go stale.
  Both stay counted as misses in the recall.
- **Deleting a rule fails the run.**
  The harness has a test that removes `S3_PUBLIC_ACCESS` and checks that the ratchet catches it.
- **Findings sit on the right type.**
  No finding may sit on a resource type its rule does not declare, and no two findings in a fixture may share an id.

## Why the expectations changed

The expectation files were written against an earlier build.
Four things changed in them for this release, each because the product changed meaning, not to raise the score:

- Public access to a bucket is now reported on the bucket, not on the `aws_s3_bucket_acl` companion that carries the setting, so two entries point at the bucket.
- `S3_NO_ENCRYPTION` now means "not encrypted with a customer-managed key" (low severity), because S3 encrypts every object with SSE-S3 already.
  A bucket with an AES256 companion therefore still gets that low finding, and the entry that said it must not was removed.
- An instance with no `metadata_options` is IMDSv1, which `EC2_IMDSV1` correctly reports.
  The hardened-resource entry for such an instance now lists the rules it is actually hardened against.
- The hard-coded Redshift password is a secret finding, so the harness had to scan through the full pipeline for it to count.

Two planted issues are not found, and the reasons are in the result above.
Both are cases where the fixture says more than its configuration proves, and a rule that reported them would be guessing from a name or a comment.

## Changing the expectations

Add a fixture to `tests/fixtures/realistic/` and a file `tests/test_quality/expected/<fixture stem>.yml` with its planted issues and hardened resources.
Each `must_find` entry names a node of the fixture's graph (a name that is not a node fails the run with a suggestion), the rules or the class of finding (`kind`, see `tests/helpers/kinds.py`) that count, and a `why` that quotes the comment or attribute that plants the issue.
A `must_not_find` entry without `rule_ids` forbids every rule finding on that resource.

When a change finds more, raise `min_recall` in `ratchet.yml` to the new measurement.
When a rule is renamed or removed, update the entries that name it: the run fails on a rule id that is not a current rule or secret detector.
Regenerate this page with `python scripts/gen_docs_counts.py --write`.
Review any change to an expectation file like a change to a test, because that is what it is.
