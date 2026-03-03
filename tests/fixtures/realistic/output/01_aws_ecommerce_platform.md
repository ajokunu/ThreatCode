# ThreatCode Threat Model Report

**Scanned resources:** 23
**Total threats:** 25
**Timestamp:** 2026-03-02T18:39:51.206785+00:00

## Summary

| Severity | Count |
|----------|-------|
| :red_circle: Critical | 2 |
| :orange_circle: High | 6 |
| :yellow_circle: Medium | 14 |
| :blue_circle: Low | 3 |

## Denial Of Service

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `aws_lambda_function.order_processor` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

## Elevation Of Privilege

### :red_circle: IAM policy with wildcard actions

**Severity:** Critical | **Resource:** `aws_iam_policy.s3_full_access` | **Source:** rule
**MITRE ATT&CK:** T1078.004

The IAM policy grants wildcard \(*\) actions, providing unrestricted access to AWS services. This violates least privilege and could allow an attacker to escalate privileges across the account.

> **Mitigation:** Replace wildcard actions with specific, scoped actions following the principle of least privilege. Use AWS Access Analyzer to identify required permissions.

### :orange_circle: Lambda function with broad execution role

**Severity:** High | **Resource:** `aws_lambda_function.order_processor` | **Source:** rule
**MITRE ATT&CK:** T1078.004

The Lambda function's execution role may have overly broad permissions, allowing it to access resources beyond its intended scope.

> **Mitigation:** Apply the principle of least privilege to the Lambda execution role. Use separate roles per function with only the permissions needed for that function's purpose.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `aws_lambda_function.order_processor` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

## Information Disclosure

### :red_circle: S3 bucket allows public access

**Severity:** Critical | **Resource:** `aws_s3_bucket.product_images` | **Source:** rule
**MITRE ATT&CK:** T1530, T1190

The S3 bucket ACL or policy allows public read or write access. This can lead to data exposure or unauthorized data modification.

> **Mitigation:** Set ACL to 'private' and use aws_s3_bucket_public_access_block to block all public access at the bucket level.

### :orange_circle: EC2 instance with public IP address

**Severity:** High | **Resource:** `aws_instance.bastion` | **Source:** rule
**MITRE ATT&CK:** T1190

The EC2 instance is configured with a public IP address, directly exposing it to internet traffic. This increases the attack surface significantly.

> **Mitigation:** Remove public IP association and use a load balancer or bastion host for access. Place instances in private subnets.

### :orange_circle: RDS instance without encryption at rest

**Severity:** High | **Resource:** `aws_db_instance.sessions` | **Source:** rule
**MITRE ATT&CK:** T1530

The RDS instance does not have storage encryption enabled. Data stored in the database can be read if the underlying storage is compromised.

> **Mitigation:** Enable storage encryption using AWS KMS. Note: encryption must be enabled at creation time and cannot be added to existing instances without migration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.product_images` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.app_logs` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :yellow_circle: EC2 instance with unencrypted root volume

**Severity:** Medium | **Resource:** `aws_instance.web_b` | **Source:** rule
**MITRE ATT&CK:** T1530

The EC2 instance root block device is not encrypted. Data on the volume can be accessed if the underlying storage media is compromised.

> **Mitigation:** Enable EBS encryption on all volumes using AWS-managed or customer-managed KMS keys.

### :yellow_circle: EC2 instance with unencrypted root volume

**Severity:** Medium | **Resource:** `aws_instance.bastion` | **Source:** rule
**MITRE ATT&CK:** T1530

The EC2 instance root block device is not encrypted. Data on the volume can be accessed if the underlying storage media is compromised.

> **Mitigation:** Enable EBS encryption on all volumes using AWS-managed or customer-managed KMS keys.

## Repudiation

### :yellow_circle: VPC without flow logs enabled

**Severity:** Medium | **Resource:** `aws_vpc.ecommerce` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The VPC does not have flow logs configured. Without flow logs, network traffic patterns cannot be analyzed for security incidents or anomalies.

> **Mitigation:** Enable VPC flow logs and direct them to CloudWatch Logs or S3 for analysis. Consider using a REJECT-only filter to reduce log volume while capturing blocked traffic.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.product_images` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.app_logs` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :blue_circle: EC2 instance without detailed monitoring

**Severity:** Low | **Resource:** `aws_instance.web_b` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The EC2 instance does not have detailed monitoring enabled. Without monitoring, unauthorized access or resource abuse may go undetected and actions cannot be attributed.

> **Mitigation:** Enable detailed monitoring and configure CloudWatch alarms for suspicious activity patterns.

### :blue_circle: EC2 instance without detailed monitoring

**Severity:** Low | **Resource:** `aws_instance.bastion` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The EC2 instance does not have detailed monitoring enabled. Without monitoring, unauthorized access or resource abuse may go undetected and actions cannot be attributed.

> **Mitigation:** Enable detailed monitoring and configure CloudWatch alarms for suspicious activity patterns.

## Tampering

### :orange_circle: Trust boundary crossing: internet -\> private

**Severity:** High | **Resource:** `aws_internet_gateway.main` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_internet_gateway.main \(internet zone\) to aws_vpc.ecommerce \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: RDS instance without automated backups

**Severity:** Medium | **Resource:** `aws_db_instance.sessions` | **Source:** rule
**MITRE ATT&CK:** T1485

The RDS instance has backup retention set to 0 or not configured. Without backups, data loss from deletion or corruption cannot be recovered.

> **Mitigation:** Set backup_retention_period to at least 7 days. Enable automated backups and consider cross-region backup replication.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.product_images` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.app_logs` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.public_a` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.public_a \(dmz zone\) to aws_vpc.ecommerce \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.public_b` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.public_b \(dmz zone\) to aws_vpc.ecommerce \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_lb.storefront` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_lb.storefront \(dmz zone\) to aws_security_group.alb_sg \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_lb.storefront` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_lb.storefront \(dmz zone\) to aws_security_group.alb_sg \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: private -\> management

**Severity:** Medium | **Resource:** `aws_lambda_function.order_processor` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_lambda_function.order_processor \(private zone\) to aws_iam_role.ec2_app_role \(management zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.
