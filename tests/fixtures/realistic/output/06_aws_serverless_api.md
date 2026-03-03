# ThreatCode Threat Model Report

**Scanned resources:** 36
**Total threats:** 19
**Timestamp:** 2026-03-02T20:19:38.621774+00:00

## Summary

| Severity | Count |
|----------|-------|
| :orange_circle: High | 3 |
| :yellow_circle: Medium | 11 |
| :blue_circle: Low | 5 |

## Denial Of Service

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `AuthFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `AccountsFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `TransfersFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `NotificationsFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `AuditLogFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

## Elevation Of Privilege

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `AuthFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `AccountsFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `TransfersFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `NotificationsFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `AuditLogFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

## Information Disclosure

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `StatementsBucket` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `PartnerDocsBucket` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `PartnerDocsBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

## Repudiation

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `StatementsBucket` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `PartnerDocsBucket` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `PartnerDocsBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

## Tampering

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `StatementsBucket` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `PartnerDocsBucket` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `PartnerDocsBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.
