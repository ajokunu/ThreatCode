# ThreatCode Threat Model Report

**Scanned resources:** 37
**Total threats:** 34
**Timestamp:** 2026-03-02T18:45:30.609409+00:00

## Summary

| Severity | Count |
|----------|-------|
| :red_circle: Critical | 2 |
| :orange_circle: High | 8 |
| :yellow_circle: Medium | 21 |
| :blue_circle: Low | 3 |

## Denial Of Service

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `aws_lambda_function.player_stats` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `aws_lambda_function.chat_handler` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

## Elevation Of Privilege

### :red_circle: IAM policy with wildcard actions

**Severity:** Critical | **Resource:** `aws_iam_policy.game_server` | **Source:** rule
**MITRE ATT&CK:** T1078.004

The IAM policy grants wildcard \(*\) actions, providing unrestricted access to AWS services. This violates least privilege and could allow an attacker to escalate privileges across the account.

> **Mitigation:** Replace wildcard actions with specific, scoped actions following the principle of least privilege. Use AWS Access Analyzer to identify required permissions.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `aws_lambda_function.player_stats` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

## Information Disclosure

### :red_circle: S3 bucket allows public access

**Severity:** Critical | **Resource:** `aws_s3_bucket_acl.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1530, T1190

The S3 bucket ACL or policy allows public read or write access. This can lead to data exposure or unauthorized data modification.

> **Mitigation:** Set ACL to 'private' and use aws_s3_bucket_public_access_block to block all public access at the bucket level.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_acl.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.player_data` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_public_access_block.player_data` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_server_side_encryption_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_lifecycle_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: EC2 instance with public IP address

**Severity:** High | **Resource:** `aws_instance.game_server_1` | **Source:** rule
**MITRE ATT&CK:** T1190

The EC2 instance is configured with a public IP address, directly exposing it to internet traffic. This increases the attack surface significantly.

> **Mitigation:** Remove public IP association and use a load balancer or bastion host for access. Place instances in private subnets.

### :yellow_circle: EC2 instance with unencrypted root volume

**Severity:** Medium | **Resource:** `aws_instance.game_server_1` | **Source:** rule
**MITRE ATT&CK:** T1530

The EC2 instance root block device is not encrypted. Data on the volume can be accessed if the underlying storage media is compromised.

> **Mitigation:** Enable EBS encryption on all volumes using AWS-managed or customer-managed KMS keys.

## Repudiation

### :yellow_circle: VPC without flow logs enabled

**Severity:** Medium | **Resource:** `aws_vpc.stormforge` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The VPC does not have flow logs configured. Without flow logs, network traffic patterns cannot be analyzed for security incidents or anomalies.

> **Mitigation:** Enable VPC flow logs and direct them to CloudWatch Logs or S3 for analysis. Consider using a REJECT-only filter to reduce log volume while capturing blocked traffic.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_acl.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.player_data` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_public_access_block.player_data` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_server_side_encryption_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_lifecycle_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :blue_circle: EC2 instance without detailed monitoring

**Severity:** Low | **Resource:** `aws_instance.game_server_1` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The EC2 instance does not have detailed monitoring enabled. Without monitoring, unauthorized access or resource abuse may go undetected and actions cannot be attributed.

> **Mitigation:** Enable detailed monitoring and configure CloudWatch alarms for suspicious activity patterns.

## Tampering

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_acl.game_assets` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.player_data` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_public_access_block.player_data` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_server_side_encryption_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_lifecycle_configuration.replay_storage` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.public_a` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.public_a \(dmz zone\) to aws_vpc.stormforge \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.public_b` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.public_b \(dmz zone\) to aws_vpc.stormforge \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_instance.game_server_1` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_instance.game_server_1 \(dmz zone\) to aws_security_group.game_server_sg \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_instance.game_server_1` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_instance.game_server_1 \(dmz zone\) to aws_security_group.game_server_test_sg \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.
