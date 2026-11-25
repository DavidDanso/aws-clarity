# Audit AWS Clarity in 10 Minutes

This guide lets an independent AWS security engineer verify how **AWS Clarity** handles credentials, AWS API calls, data minimization, read-only enforcement, and browser privacy directly from the source code—without reading the whole repository.

---

## A. Where Credentials Are Handled

All credential resolution uses the standard AWS SDK (`boto3`) provider chain on the user's workstation. AWS Clarity never prompts for, logs, prints, or persists AWS secret keys or session tokens.

| Responsibility | Exact Source File & Symbols |
| --- | --- |
| Local `boto3.Session`, `--profile`, SSO expiry guidance, explicit `ProfileNotFound` refusal (never falls back silently), and optional local `--role-arn` / `--external-id` STS assumption | `backend/local_engine.py`: `create_local_session()`, `verify_identity()`, `describe_credential_source()` |
| Root ARN refusal by default (`--allow-root` required to override) & name-only admin heuristic warning (zero extra IAM calls) | `backend/local_engine.py`: `is_root_arn()`, `is_likely_admin_name_heuristic()`, `enforce_identity_guards()`<br>`backend/exceptions.py`: `RootIdentityBlockedError` |
| CLI pre-scan confirmation (`[y/N]` / `--yes`), Account ID & Caller ARN masking (`********9012`), owner-only report file write (`0600` on POSIX) | `backend/aws_clarity_cli.py`: `_print_prescan_confirmation_and_prompt()`, `_write_secure_json()`, `cmd_doctor()`, `cmd_scan()` |
| Credential & access-key scrubbing on error messages | `backend/utils.py`: `redact_credential_strings()` |
| Customer-deployable least-privilege read-only IAM role template | `infra/aws-clarity-readonly-role.yaml` |

---

## B. Where AWS API Calls Happen (Authoritative Allowlist)

Every AWS API call in the local CLI passes through **`backend/api_guard.py`** (`ALLOWED_AWS_OPERATIONS` + `GuardedClient`). The IAM policy returned by `aws-clarity policy` is derived directly from `api_guard.get_allowed_iam_actions()` so runtime calls and documented permissions cannot drift.

- **Default zero-request-charge scope (9 services, 28 actions):**
  - **STS / Account (`backend/local_engine.py`):** `sts:GetCallerIdentity` *(plus `sts:AssumeRole` isolated strictly to `create_local_session()` when `--role-arn` is explicitly passed)*
  - **EC2 (`backend/lambda_handler.py`, `backend/scanner/ec2.py`, `elastic_ip.py`, `security_group.py`):** `ec2:DescribeRegions`, `ec2:DescribeInstances`, `ec2:DescribeAddresses`, `ec2:DescribeSecurityGroups`
  - **VPC (`backend/scanner/vpcs.py`, `internet_gateways.py`, `nat_gateways.py`):** `ec2:DescribeVpcs`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`
  - **EBS (`backend/scanner/ebs.py`, `snapshots.py`):** `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`
  - **IAM (`backend/scanner/iam.py`):** `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`
  - **Lambda (`backend/scanner/lambda_functions.py`):** `lambda:ListFunctions`
  - **RDS (`backend/scanner/rds.py`):** `rds:DescribeDBInstances`
  - **DynamoDB (`backend/scanner/dynamodb_tables.py`):** `dynamodb:ListTables`, `dynamodb:DescribeTable`
  - **CloudWatch (`backend/scanner/cloudwatch.py`):** `cloudwatch:DescribeAlarms`, `logs:DescribeLogGroups`
  - **CloudTrail (`backend/scanner/cloudtrail.py`):** `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`
- **Optional S3 metadata scope (1 service, 6 actions — OFF by default; requires `--include-s3-checks` + cost consent):**
  - `backend/scanner/s3.py` & `backend/scanner/misconfig.py`: `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration`, `s3:GetBucketPublicAccessBlock`.
  - **Never called:** `s3:ListBucket`, `s3:ListObjectsV2`, `s3:GetObject`, Cost Explorer, GuardDuty, Security Hub, AWS Config, or any write/delete API.

---

## C. Where Data Is Collected & Minimized

All 15 collectors live in `backend/scanner/` and extract explicit field allowlists before returning resources:

- **Dropped at the collector boundary:** All `Tags` arrays (keeping only sanitized `Name` where needed for display), EC2 `PrivateIpAddress` / `UserData`, free-text `Description` fields (Security Groups, ingress rules, Snapshots, Lambda, CloudWatch Alarms), `Lambda.Environment.Variables` (replaced with boolean `has_environment_variables`), RDS `Endpoint.Address` / `MasterUsername` / `KmsKeyId`, DynamoDB `KMSMasterKeyArn`, CloudWatch Alarm `Dimensions` & full SNS action ARNs, Log Group `kmsKeyId`, CloudTrail `KmsKeyId` & `LatestDeliveryError` text, and IAM policy `Sid` + literal `Condition` values (including `sts:ExternalId` secret values) + scoped `Resource` ARNs (`[scoped-resource]`).
- **Pruned post-evaluation before report serialization:** `backend/local_engine.py:_minimize_report_resources_post_eval()` removes `inline_policies` and `trust_policy` from `raw` after `backend/scanner/misconfig.py:evaluate()` finishes, retaining only `inline_policy_names`, `inline_policy_count`, and `trust_statement_count`.
- **Report serialization:** `backend/aws_clarity_cli.py:_write_secure_json()` writes JSON locally with mode `0600` on POSIX (standard user directory ACLs on Windows).

---

## D. How Read-Only Behavior Is Enforced

1. **Client-layer runtime enforcement (`backend/api_guard.py` + `backend/utils.py:CachedSession`):** Every boto3 client created by `run_doctor()` and `run_local_scan()` is wrapped in `GuardedClient`, which intercepts calls at **both** the botocore `before-call.*.*` event hook and the Python method/paginator proxy. Any AWS mutation (`terminate_instances`, `delete_bucket`, etc.), any unlisted read (`get_object`, `get_secret_value`, `describe_tags`), and any S3 operation when `include_s3=False` raises `DisallowedAWSOperationError` before any network call.
2. **1:1 IAM policy parity:** `build_policy_document()` in `backend/local_engine.py`, `infra/aws-clarity-readonly-role.yaml`, and `frontend/src/utils/constants.js` are tested for exact 28/34-action parity.
3. **Static AST audit & zero-telemetry test:** `backend/test_phase1_hardening.py` parses the AST of every local scanner file to assert zero mutating AWS method names and hooks `socket.getaddrinfo` / `urllib.request.urlopen` to verify zero non-AWS network destinations.

---

## E. How Browser Privacy Is Enforced

- **No backend / zero report uploads:** The web app (`frontend/`) is a pure static React SPA with zero `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, IndexedDB, service worker, or cookie usage.
- **Content Security Policy:** `frontend/vite.config.js` injects `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'" />` into `dist/index.html`. `infra/cloudfront.tf` defines the matching HTTP `aws_cloudfront_response_headers_policy` adding `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and `Strict-Transport-Security`.
- **Untrusted report validation (`frontend/src/utils/reportImporter.js`):** 25 MB size limit (checked before `file.text()`), prototype-pollution stripping (`__proto__`, `constructor`, `prototype`), credential key/pattern blocking (case/separator-normalized keys, secret assignments, `FwoGZXIvYXdz...` STS tokens, `ASIA...` temporary keys), strict status/severity validation, deduplication, and control-character stripping.
- **In-memory only:** `frontend/src/App.jsx` keeps `scanResults` and `previousScanResults` strictly in React state (never saved to `localStorage`/`sessionStorage`), cleared via Trust & Privacy controls or tab reload/close.
- **Exports (`frontend/src/utils/reportSanitizer.js`):** Best-effort Sanitized JSON/CSV redacts Account IDs, ARNs, access key IDs, AWS resource IDs, resource names, and non-wildcard IPv4/IPv6 addresses/CIDRs; CSV exports neutralize formula prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`, and leading spaces before formula characters).

---

## F. Reproduce All Verification Suites Locally

```bash
# 1. Backend unit tests + Phase 1 security + Phase 2 scanner matrix + Phase 4 release integrity
python3 -m unittest discover -s backend -p "test_*.py" -v < /dev/null

# 2. Frontend lint, production build, and Phase 1–3 security/correctness scripts
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run verify
node frontend/scripts/verify-phase1-canary.mjs
node frontend/scripts/verify-phase2-correctness.mjs
node frontend/scripts/verify-phase3-security.mjs

# 3. Optional: End-to-end headless Chrome security test against local frontend/dist
# (Requires playwright-core installed in an isolated directory + local Chrome/Chromium)
PLAYWRIGHT_CORE_DIR=/path/to/pw-runner node frontend/scripts/verify-phase3-browser.mjs

# 4. Dependency vulnerability audits
npm --prefix frontend audit
pip-audit -r backend/requirements.txt
```

---

## G. Honest Security Limitations

- **No third-party audit or certification:** AWS Clarity is an independent open-source project; it has **not** undergone an independent penetration test or SOC 2 / ISO 27001 certification.
- **Mocked tests vs live AWS environments:** Automated backend tests run against mocked boto3/botocore responses and synthetic fixtures, not live production AWS accounts.
- **Local CLI trust boundary:** Anyone who compromises the user's workstation or installs a tampered package inherits whatever permissions the user's active AWS credentials hold. Always prefer a dedicated least-privilege read-only IAM role (`infra/aws-clarity-readonly-role.yaml`) and verify `SHA256SUMS.txt` + GitHub build provenance attestations.
- **Residual risk in reports:** Unsanitized local reports retain resource names, IDs, ARNs, public IPs, and CIDRs so users can identify findings; on Windows, file permissions rely on user-directory ACLs rather than POSIX `0600`.
- **Sanitized exports are best-effort:** Best-effort redaction cannot guarantee complete anonymity if custom strings or indirect metadata identify an organization—always inspect sanitized files before sharing.
- **Browser memory:** Clearing in-memory reports drops JavaScript references for garbage collection; browser JavaScript cannot guarantee physical RAM zeroization.
