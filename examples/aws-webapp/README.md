# aws-webapp

A small web stack on AWS, as `terraform show -json` prints it.

An internet-facing application load balancer (443 open to the world) fronts two app instances that still allow IMDSv1.
The instances share an instance profile whose role may read the customer data bucket and the database secret.
The database accepts 5432 from the app security group only.
`scanner/trivy-app-image.json` is a Trivy report with one critical CVE in the base of the image the instances run.

Files:

| File | What it is |
|------|------------|
| `tfplan.json` | The plan: VPC, public and private subnets, route table, security groups, load balancer, listener, target group, two instances, role, policy and instance profile, database, bucket, secret. |
| `scanner/trivy-app-image.json` | Trivy JSON for `registry.example.com/shop/orders-api:3.2.1`. |
| `expected.yml` | What a scan must produce, read by the test suite. |

## Scan the plan

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp
```

Exit code 1: the gate tripped.
In a terminal the report is:

<!-- gen:report -->
```text
ThreatCode scan of .: 28 resources, 12 findings

Verdict: 5 high, 6 medium, 1 low, 3 attack paths from the internet to data

Attack paths (3)
CRITICAL  internet -> aws_s3_bucket.customer_data  (5 hops, id 5453d439158d)
          internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app >
          aws_iam_role.app > aws_s3_bucket.customer_data
HIGH      internet -> aws_secretsmanager_secret.db_credentials  (5 hops, id 1e87639aaf0e)
          internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app >
          aws_iam_role.app > aws_secretsmanager_secret.db_credentials
HIGH      internet -> aws_db_instance.orders  (3 hops, id e716deafaabc)
          internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders

Findings (12)
SEVERITY  RESOURCE           RULE                       FINDING                      LOCATION
HIGH      aws_in...e.app[0]  EC2_IMDSV1                 EC2 instance metadata se...  tfplan.json:484
HIGH      aws_in...e.app[1]  EC2_IMDSV1                 EC2 instance metadata se...  tfplan.json:532
HIGH      aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
HIGH      aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
HIGH      aws_s3...mer_data  S3_NO_VERSIONING           S3 bucket without versio...  tfplan.json:660
MEDIUM    aws_in...e.app[0]  boundary                   Trust boundary crossing:...  tfplan.json:484
MEDIUM    aws_in...e.app[1]  boundary                   Trust boundary crossing:...  tfplan.json:532
MEDIUM    aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
MEDIUM    aws_s3...mer_data  S3_NO_LOGGING              S3 bucket without access...  tfplan.json:660
MEDIUM    aws_se...dentials  SM_NO_ROTATION             Secrets Manager secret w...  tfplan.json:721
MEDIUM    aws_vpc.main       VPC_NO_FLOW_LOGS           VPC without flow logs        tfplan.json:12
LOW       aws_se...roup.alb  SG_WEB_PORT_OPEN_TO_WORLD  Security group allows th...  tfplan.json:219

Coverage: 3 files discovered, 1 unit parsed, 2 not infrastructure
  No input errors or coverage gaps were recorded.
```
<!-- /gen:report -->

The attack paths, all from the `internet` node:

<!-- gen:paths -->
1. **critical**, 5 hops, id `5453d439158d`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_iam_instance_profile.app` -> `aws_iam_role.app` -> `aws_s3_bucket.customer_data`
   ATT&CK techniques: T1190, T1552.005, T1078.004, T1530.
2. **high**, 3 hops, id `e716deafaabc`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_db_instance.orders`
   ATT&CK techniques: T1190, T1552.005.
3. **high**, 5 hops, id `1e87639aaf0e`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_iam_instance_profile.app` -> `aws_iam_role.app` -> `aws_secretsmanager_secret.db_credentials`
   ATT&CK techniques: T1190, T1552.005, T1078.004.
<!-- /gen:paths -->

Read the first path from the internet.
Port 443 of the load balancer is open to the world (`SG_WEB_PORT_OPEN_TO_WORLD` enables that hop).
The load balancer reaches the instances on 8080.
An instance still allows IMDSv1 (`EC2_IMDSV1` enables the next hop), so a request forgery in the app can read the temporary credentials of the instance role.
The role may `s3:GetObject` on the customer data bucket, and the bucket is tagged confidential, which is why its path is critical.
The other two paths end at the database secret (`secretsmanager:GetSecretValue` on the secret's ARN) and at the database, which only the app tier can reach.

## Join the Trivy report

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json
```

The image reference `registry.example.com/shop/orders-api:3.2.1` appears in the instances' user data, so the CVE lands on both instances and is not an unplaced line in a list.
Each path crosses an instance, and the critical CVE raises all three to critical:

<!-- gen:report-ingest -->
```text
ThreatCode scan of .: 28 resources, 14 findings

Verdict: 2 critical, 5 high, 6 medium, 1 low, 3 attack paths from the internet to data

Attack paths (3)
CRITICAL  internet -> aws_s3_bucket.customer_data  (5 hops, id 5453d439158d)
          internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app >
          aws_iam_role.app > aws_s3_bucket.customer_data
CRITICAL  internet -> aws_secretsmanager_secret.db_credentials  (5 hops, id 1e87639aaf0e)
          internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app >
          aws_iam_role.app > aws_secretsmanager_secret.db_credentials
CRITICAL  internet -> aws_db_instance.orders  (3 hops, id e716deafaabc)
          internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders

Findings (14)
SEVERITY  RESOURCE           RULE                       FINDING                      LOCATION
CRITICAL  aws_in...e.app[0]  trivy:CVE-2022-37434       CVE-2022-37434: zlib: he...  tfplan.json:484
CRITICAL  aws_in...e.app[1]  trivy:CVE-2022-37434       CVE-2022-37434: zlib: he...  tfplan.json:532
HIGH      aws_in...e.app[0]  EC2_IMDSV1                 EC2 instance metadata se...  tfplan.json:484
HIGH      aws_in...e.app[1]  EC2_IMDSV1                 EC2 instance metadata se...  tfplan.json:532
HIGH      aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
HIGH      aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
HIGH      aws_s3...mer_data  S3_NO_VERSIONING           S3 bucket without versio...  tfplan.json:660
MEDIUM    aws_in...e.app[0]  boundary                   Trust boundary crossing:...  tfplan.json:484
MEDIUM    aws_in...e.app[1]  boundary                   Trust boundary crossing:...  tfplan.json:532
MEDIUM    aws_lb.front       boundary                   Trust boundary crossing:...  tfplan.json:351
MEDIUM    aws_s3...mer_data  S3_NO_LOGGING              S3 bucket without access...  tfplan.json:660
MEDIUM    aws_se...dentials  SM_NO_ROTATION             Secrets Manager secret w...  tfplan.json:721
MEDIUM    aws_vpc.main       VPC_NO_FLOW_LOGS           VPC without flow logs        tfplan.json:12
LOW       aws_se...roup.alb  SG_WEB_PORT_OPEN_TO_WORLD  Security group allows th...  tfplan.json:219

Coverage: 3 files discovered, 1 unit parsed, 2 not infrastructure
  No input errors or coverage gaps were recorded.
```
<!-- /gen:report-ingest -->

<!-- gen:paths-ingest -->
1. **critical**, 5 hops, id `5453d439158d`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_iam_instance_profile.app` -> `aws_iam_role.app` -> `aws_s3_bucket.customer_data`
   ATT&CK techniques: T1190, T1552.005, T1078.004, T1530.
2. **critical**, 3 hops, id `e716deafaabc`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_db_instance.orders`
   ATT&CK techniques: T1190, T1552.005.
3. **critical**, 5 hops, id `1e87639aaf0e`: `internet` -> `aws_lb.front` -> `aws_instance.app[0]` -> `aws_iam_instance_profile.app` -> `aws_iam_role.app` -> `aws_secretsmanager_secret.db_credentials`
   ATT&CK techniques: T1190, T1552.005, T1078.004.
<!-- /gen:paths-ingest -->

## Write the formats

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp --fail-on none -f markdown -o report.md
threatcode scan examples/aws-webapp --fail-on none -f sarif -o threatcode.sarif
threatcode scan examples/aws-webapp --fail-on none -f mermaid -o paths.mmd
threatcode scan examples/aws-webapp --fail-on none -f diagram -o threat-model.svg
```
