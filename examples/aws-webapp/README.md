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
ThreatCode scan of examples/aws-webapp: 28 resources, 12 findings

Verdict: 5 high, 6 medium, 1 low, 3 attack paths from the internet to data stores and secret stores,
         worst critical

Attack paths (3)
P1  CRITICAL  internet -> aws_s3_bucket.customer_data
    data store, 5 hops, score 9.2; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_s3_bucket.customer_data
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: HIGH EC2_IMDSV1
    ignore id: 5453d439158d

P2  HIGH      internet -> aws_secretsmanager_secret.db_credentials
    secret store, 5 hops, score 7.5; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_secretsmanager_secret.db_credentials
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: HIGH EC2_IMDSV1
    ignore id: 1e87639aaf0e

P3  HIGH      internet -> aws_db_instance.orders
    data store, 3 hops, score 7.5; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_db_instance.orders on tcp/5432: HIGH EC2_IMDSV1
    ignore id: e716deafaabc

Findings (12)
SEVERITY  RESOURCE                                  RULE                       PATHS
          FINDING  LOCATION  ATT&CK  STRIDE
HIGH^     aws_instance.app[0]                       EC2_IMDSV1                 P1,P2+1
          EC2 instance metadata service allows IMDSv1  tfplan.json:484  T1552.005  EoP
HIGH^     aws_instance.app[1]                       EC2_IMDSV1
          EC2 instance metadata service allows IMDSv1  tfplan.json:532  T1552.005  EoP
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[1] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH^     aws_s3_bucket.customer_data               S3_NO_VERSIONING
          S3 bucket without versioning  tfplan.json:660  T1485  DoS
MEDIUM    aws_instance.app[0]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:484  T1530,T1565.002  Tampering
MEDIUM    aws_instance.app[1]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:532  T1530,T1565.002  Tampering
MEDIUM    aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, internet > dmz: from the internet (tcp/443)  tfplan.json:351
          T1190,T1565.002  Tampering
MEDIUM^   aws_s3_bucket.customer_data               S3_NO_LOGGING
          S3 bucket without access logging  tfplan.json:660  Repudiation
MEDIUM    aws_secretsmanager_secret.db_credentials  SM_NO_ROTATION
          Secrets Manager secret without rotation  tfplan.json:721  T1555.006  Info disclosure
MEDIUM    aws_vpc.main                              VPC_NO_FLOW_LOGS
          VPC without flow logs  tfplan.json:12  Repudiation
LOW       aws_security_group.alb                    SG_WEB_PORT_OPEN_TO_WORLD  P1,P2+1
          Security group allows the internet to reach a web port  tfplan.json:219  T1190  Info
          disclosure
Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths above that the
     finding enables

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
ThreatCode scan of examples/aws-webapp: 28 resources, 14 findings

Verdict: 2 critical, 5 high, 6 medium, 1 low, 3 attack paths from the internet to data stores and
         secret stores, worst critical

Attack paths (3)
P1  CRITICAL  internet -> aws_s3_bucket.customer_data
    data store, 5 hops, score 9.2; 3 findings enable it, the worst being CRITICAL
    trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_s3_bucket.customer_data
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: CRITICAL trivy:CVE-2022-37434, HIGH
        EC2_IMDSV1
    ignore id: 5453d439158d

P2  CRITICAL  internet -> aws_secretsmanager_secret.db_credentials
    secret store, 5 hops, score 9; 3 findings enable it, the worst being CRITICAL
    trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_secretsmanager_secret.db_credentials
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: CRITICAL trivy:CVE-2022-37434, HIGH
        EC2_IMDSV1
    ignore id: 1e87639aaf0e

P3  CRITICAL  internet -> aws_db_instance.orders
    data store, 3 hops, score 9; 3 findings enable it, the worst being CRITICAL
    trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_db_instance.orders on tcp/5432: CRITICAL trivy:CVE-2022-37434, HIGH
        EC2_IMDSV1
    ignore id: e716deafaabc

Findings (14)
SEVERITY  RESOURCE                                  RULE                       PATHS
          FINDING  LOCATION  ATT&CK  STRIDE
CRITICAL  aws_instance.app[0]                       trivy:CVE-2022-37434       P1,P2+1
          CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate() in inflate.c
          via a large gzip header extra field  tfplan.json:484  EoP
CRITICAL  aws_instance.app[1]                       trivy:CVE-2022-37434
          CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate() in inflate.c
          via a large gzip header extra field  tfplan.json:532  EoP
HIGH^     aws_instance.app[0]                       EC2_IMDSV1                 P1,P2+1
          EC2 instance metadata service allows IMDSv1  tfplan.json:484  T1552.005  EoP
HIGH^     aws_instance.app[1]                       EC2_IMDSV1
          EC2 instance metadata service allows IMDSv1  tfplan.json:532  T1552.005  EoP
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[1] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH^     aws_s3_bucket.customer_data               S3_NO_VERSIONING
          S3 bucket without versioning  tfplan.json:660  T1485  DoS
MEDIUM    aws_instance.app[0]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:484  T1530,T1565.002  Tampering
MEDIUM    aws_instance.app[1]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:532  T1530,T1565.002  Tampering
MEDIUM    aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, internet > dmz: from the internet (tcp/443)  tfplan.json:351
          T1190,T1565.002  Tampering
MEDIUM^   aws_s3_bucket.customer_data               S3_NO_LOGGING
          S3 bucket without access logging  tfplan.json:660  Repudiation
MEDIUM    aws_secretsmanager_secret.db_credentials  SM_NO_ROTATION
          Secrets Manager secret without rotation  tfplan.json:721  T1555.006  Info disclosure
MEDIUM    aws_vpc.main                              VPC_NO_FLOW_LOGS
          VPC without flow logs  tfplan.json:12  Repudiation
LOW       aws_security_group.alb                    SG_WEB_PORT_OPEN_TO_WORLD  P1,P2+1
          Security group allows the internet to reach a web port  tfplan.json:219  T1190  Info
          disclosure
Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths above that the
     finding enables

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
