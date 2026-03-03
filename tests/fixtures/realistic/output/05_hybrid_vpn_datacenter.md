# ThreatCode Threat Model Report

**Scanned resources:** 38
**Total threats:** 19
**Timestamp:** 2026-03-02T18:41:47.609644+00:00

## Summary

| Severity | Count |
|----------|-------|
| :orange_circle: High | 6 |
| :yellow_circle: Medium | 12 |
| :blue_circle: Low | 1 |

## Information Disclosure

### :orange_circle: EC2 instance with public IP address

**Severity:** High | **Resource:** `aws_instance.vpn_concentrator` | **Source:** rule
**MITRE ATT&CK:** T1190

The EC2 instance is configured with a public IP address, directly exposing it to internet traffic. This increases the attack surface significantly.

> **Mitigation:** Remove public IP association and use a load balancer or bastion host for access. Place instances in private subnets.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_versioning.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_lifecycle_configuration.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :orange_circle: S3 bucket without server-side encryption

**Severity:** High | **Resource:** `aws_s3_bucket_public_access_block.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1530

The S3 bucket does not have server-side encryption configured. Data at rest may be accessible if storage media is compromised.

> **Mitigation:** Enable server-side encryption using AES-256 \(SSE-S3\) or AWS KMS \(SSE-KMS\) via aws_s3_bucket_server_side_encryption_configuration.

### :yellow_circle: EC2 instance with unencrypted root volume

**Severity:** Medium | **Resource:** `aws_instance.vpn_concentrator` | **Source:** rule
**MITRE ATT&CK:** T1530

The EC2 instance root block device is not encrypted. Data on the volume can be accessed if the underlying storage media is compromised.

> **Mitigation:** Enable EBS encryption on all volumes using AWS-managed or customer-managed KMS keys.

## Repudiation

### :yellow_circle: VPC without flow logs enabled

**Severity:** Medium | **Resource:** `aws_vpc.hub` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The VPC does not have flow logs configured. Without flow logs, network traffic patterns cannot be analyzed for security incidents or anomalies.

> **Mitigation:** Enable VPC flow logs and direct them to CloudWatch Logs or S3 for analysis. Consider using a REJECT-only filter to reduce log volume while capturing blocked traffic.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_versioning.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_lifecycle_configuration.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :yellow_circle: S3 bucket without access logging

**Severity:** Medium | **Resource:** `aws_s3_bucket_public_access_block.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The S3 bucket does not have access logging configured. Without logging, unauthorized access attempts cannot be detected and actions cannot be attributed to specific actors.

> **Mitigation:** Enable server access logging via aws_s3_bucket_logging resource, directing logs to a separate dedicated logging bucket.

### :blue_circle: EC2 instance without detailed monitoring

**Severity:** Low | **Resource:** `aws_instance.vpn_concentrator` | **Source:** rule
**MITRE ATT&CK:** T1562.008

The EC2 instance does not have detailed monitoring enabled. Without monitoring, unauthorized access or resource abuse may go undetected and actions cannot be attributed.

> **Mitigation:** Enable detailed monitoring and configure CloudWatch alarms for suspicious activity patterns.

## Tampering

### :orange_circle: Trust boundary crossing: internet -\> private

**Severity:** High | **Resource:** `aws_internet_gateway.hub` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_internet_gateway.hub \(internet zone\) to aws_vpc.hub \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_versioning.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_lifecycle_configuration.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: S3 bucket without versioning

**Severity:** Medium | **Resource:** `aws_s3_bucket_public_access_block.vpn_logs` | **Source:** rule
**MITRE ATT&CK:** T1485

The S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and tampering is harder to detect.

> **Mitigation:** Enable bucket versioning via aws_s3_bucket_versioning resource to protect against accidental deletion and enable audit trails.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.dmz_a` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.dmz_a \(dmz zone\) to aws_vpc.hub \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.

### :yellow_circle: Trust boundary crossing: dmz -\> private

**Severity:** Medium | **Resource:** `aws_subnet.dmz_b` | **Source:** boundary
**MITRE ATT&CK:** T1040, T1557

Data flows from aws_subnet.dmz_b \(dmz zone\) to aws_vpc.hub \(private zone\), crossing a trust boundary. This flow should be authenticated, encrypted, and validated.

> **Mitigation:** Ensure all data crossing trust boundaries is encrypted in transit \(TLS/mTLS\), authenticated, and validated at the receiving end.
