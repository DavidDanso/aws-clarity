# Supported Services, Resource Types & Assessment Rules (v1)

AWS Clarity v1 intentionally focuses on **10 core AWS services**, **17 resource types**, and **43 deterministic rules** (plus the `CT-000` account-level CloudTrail advisory).

## Finding Categories, Severity Distribution & Status Model

- **Categories:** `Security Risk`, `Operational Concern`, `Potential Cost Waste`.
- **Rule Severity Breakdown (43 resource rules + 1 account-level advisory `CT-000`):**
  - **13 `CRITICAL`:** `SG-001`, `SG-002`, `SG-003`, `SG-004`, `S3-002`, `S3-003`, `IAM-001`, `IAM-003`, `IAM-005`, `IAM-009`, `IAM-011`, `RDS-001`, `CT-001` (plus account-level `CT-000` when scanning all enabled regions cleanly with 0 trails).
  - **20 `WARNING`:** `EC2-002`, `VPC-001`, `NAT-001`, `S3-005`, `IAM-002`, `IAM-004`, `IAM-006`, `IAM-007`, `IAM-008`, `IAM-010`, `LAM-002`, `RDS-002`, `RDS-003`, `RDS-004`, `DDB-001`, `EBS-001`, `CW-001`, `CW-003`, `CT-002`, `CT-003`.
  - **3 `UNUSED`:** `EIP-001`, `IGW-001`, `EBS-002`.
  - **7 `INFO`:** `EC2-001`, `NAT-002`, `S3-004`, `LAM-001`, `DDB-002`, `SNAP-001`, `CW-002`.
- **Resource Statuses:** `CRITICAL`, `WARNING`, `UNUSED`, `HEALTHY`, `INCOMPLETE` (no `NOT_ASSESSED` status).
- **Informational Observations (`INFO`):** Non-penalizing (`0` score deduction) review notes for configurations that are often legitimate (`NAT-002`, `LAM-001`, `SNAP-001`, `CW-002`, `EC2-001`, `DDB-002`, and `S3-004` default encryption verification). Resources with only `INFO` notes remain `HEALTHY` if all mandatory checks passed.
- **Coverage & Check Statuses:** `COMPLETE`, `INCOMPLETE`, `SKIPPED_OPTIONAL` (optional S3 checks not enabled; never counted as healthy or passed), `No Resources` (collection succeeded with 0 resources of that type), and `Check Failed` (collection or rule evaluation failed due to missing permissions, unreachable region, or missing evidence).

## 10-Service Coverage Matrix

| # | Service | Default / Optional | Resource Types | Rules |
| --- | --- | --- | --- | --- |
| 1 | **EC2** | Default (Free APIs) | EC2 Instances, Elastic IPs, Security Groups | `SG-001`–`SG-004`, `EC2-001` (`INFO`), `EC2-002`, `EIP-001` |
| 2 | **VPC** | Default (Free APIs) | VPCs, Internet Gateways, NAT Gateways | `VPC-001` (empty default VPCs pass; marks `CHECK_FAILED` if EC2/RDS discovery fails), `IGW-001`, `NAT-001`, `NAT-002` (`INFO`) |
| 3 | **S3** | **Optional (`--include-s3-checks`)** | S3 Buckets | `S3-002`, `S3-003`, `S3-004` (`INFO`), `S3-005` (`S3-001` removed to avoid `ListObjectsV2` charges) |
| 4 | **IAM** | Default (Free APIs) | IAM Roles, IAM Users | `IAM-001`–`IAM-011` (context-aware: excludes read-only `Describe/List/Get` & service-linked roles; checks restrictive conditions) |
| 5 | **Lambda** | Default (Free APIs) | Lambda Functions | `LAM-001` (`INFO`, >90d unmodified), `LAM-002` (deprecated runtime) |
| 6 | **RDS** | Default (Free APIs) | RDS DB Instances | `RDS-001`–`RDS-004` (public access, encryption, deletion protection, automated backups) |
| 7 | **DynamoDB** | Default (Free APIs) | DynamoDB Tables | `DDB-001` (AWS-owned default encryption passes), `DDB-002` (`INFO`, empty provisioned table) |
| 8 | **EBS** | Default (Free APIs) | EBS Volumes, EBS Snapshots | `EBS-001`, `EBS-002`, `SNAP-001` (`INFO`, snapshot without original volume) |
| 9 | **CloudWatch** | Default (Free APIs) | CloudWatch Alarms, CloudWatch Log Groups | `CW-001`, `CW-002` (`INFO`, `INSUFFICIENT_DATA`), `CW-003` (Never Expire) |
| 10 | **CloudTrail** | Default (Free APIs) | CloudTrail Trails | `CT-001`–`CT-003` + `CT-000` missing-trail advisory (all-regions scans only; verify Organization trails / CloudTrail Lake separately) |

## Health Score Formula

```text
Score = max(0, 100 - [10 * Critical + 4 * Warnings + 1 * Unused])
```

- `INFO` observations deduct **0 points**.
- Account-level `CRITICAL` advisories (such as `CT-000` when scanning all enabled regions cleanly with 0 trails) are included in Critical deductions so an unlogged account is not scored `100/100`.
- If **any** mandatory service, region, or resource check is `INCOMPLETE`, the numeric score is withheld and the UI displays: `"Health score unavailable — assessment incomplete."`
- The score describes **only AWS Clarity's supported v1 checks and available evidence**—it is an operational visibility metric, never a security certification or guarantee that the entire AWS account is secure.

## Known Limitations (v1)

- Does not scan AWS services outside the 10 listed above (e.g., EKS, ECS, KMS, Route 53, CloudFront, API Gateway, SQS, SNS).
- Does not estimate dollar costs (no AWS Cost Explorer calls).
- Does not inspect customer data contents (S3 objects, DB rows, Lambda code, log events).
- All remediation is manual; AWS Clarity never modifies AWS resources.
