# ThreatCode Threat Model Report

**Scanned resources:** 34
**Total threats:** 24
**Timestamp:** 2026-03-02T20:19:47.795915+00:00

## Summary

| Severity | Count |
|----------|-------|
| :orange_circle: High | 6 |
| :yellow_circle: Medium | 15 |
| :blue_circle: Low | 3 |

## Denial Of Service

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `RecordsApiFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `HL7ProcessorFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

### :blue_circle: Lambda function without dead letter queue

**Severity:** Low | **Resource:** `ReportGeneratorFunction` | **Source:** rule
**MITRE ATT&CK:** T1499

The Lambda function does not have a dead letter queue configured. Failed invocations may be silently lost, affecting reliability and making it difficult to diagnose processing failures.

> **Mitigation:** Configure a dead letter queue \(SQS or SNS\) to capture failed invocations for retry or investigation.

## Elevation Of Privilege

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `RecordsApiFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `HL7ProcessorFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

### :yellow_circle: Lambda function not attached to VPC

**Severity:** Medium | **Resource:** `ReportGeneratorFunction` | **Source:** rule
**MITRE ATT&CK:** T1190

The Lambda function runs outside a VPC, meaning it has direct internet access and cannot leverage VPC security controls like security groups and NACLs.

> **Mitigation:** Attach the Lambda function to a VPC with appropriate security groups. Use VPC endpoints for AWS service access.

## Information Disclosure

### :orange_circle: RDS instance without encryption at rest

**Severity:** High | **Resource:** `AuroraInstanceA` | **Source:** rule
**MITRE ATT&CK:** T1530

The RDS instance does not have storage encryption enabled. Data stored in the database can be read if the underlying storage is compromised.

> **Mitigation:** Enable storage encryption using AWS KMS. Note: encryption must be enabled at creation time and cannot be added to existing instances without migration.

### :orange_circle: RDS instance without encryption at rest

**Severity:** High | **Resource:** `AuroraInstanceB` | **Source:** rule
**MITRE ATT&CK:** T1530

The RDS instance does not have storage encryption enabled. Data stored in the database can be read if the underlying storage is compromised.

> **Mitigation:** Enable storage encryption using AWS KMS. Note: encryption must be enabled at creation time and cannot be added to existing instances without migration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `PatientRecordsBucket` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `AuditLogsBucket` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `TempUploadsBucket` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `CloudTrailBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

## Repudiation

### :yellow_circle: VPC without flow logs enabled

**Severity:** Medium | **Resource:** `MedVaultVPC` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The VPC does not have flow logs configured. Without flow logs, network traffic patterns cannot be analyzed for security incidents or anomalies.

> **Mitigation:** Enable VPC flow logs and direct them to CloudWatch Logs or S3 for analysis. Consider using a REJECT-only filter to reduce log volume while capturing blocked traffic.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `PatientRecordsBucket` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `AuditLogsBucket` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `TempUploadsBucket` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `CloudTrailBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

## Tampering

### :yellow_circle: RDS instance without automated backups

**Severity:** Medium | **Resource:** `AuroraInstanceA` | **Source:** rule
**MITRE ATT&CK:** T1485

The RDS instance has backup retention set to 0 or not configured. Without backups, data loss from deletion or corruption cannot be recovered.

> **Mitigation:** Set backup_retention_period to at least 7 days. Enable automated backups and consider cross-region backup replication.

### :yellow_circle: RDS instance without automated backups

**Severity:** Medium | **Resource:** `AuroraInstanceB` | **Source:** rule
**MITRE ATT&CK:** T1485

The RDS instance has backup retention set to 0 or not configured. Without backups, data loss from deletion or corruption cannot be recovered.

> **Mitigation:** Set backup_retention_period to at least 7 days. Enable automated backups and consider cross-region backup replication.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `PatientRecordsBucket` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `AuditLogsBucket` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `TempUploadsBucket` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `CloudTrailBucketPolicy` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: Trust boundary crossing: private -\> data

**Severity:** Medium | **Resource:** `HIPAACloudTrail` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from HIPAACloudTrail \(private zone\) to CloudTrailBucketPolicy \(data zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.
