# Security Architecture & Privacy Data Handling

## 1. Local-First Data Flow

```text
[Customer Workstation]
  aws-clarity CLI (Python 3.10+, pinned boto3/botocore)
    ├── Uses local AWS CLI / IAM Identity Center credentials
    ├── Contacts ONLY official AWS API endpoints (*.amazonaws.com)
    └── Writes local aws-clarity-report.json (mode 0600, zero credentials)

[Customer Browser]
  Static AWS Clarity Website (CSP: connect-src 'none')
    ├── Parses imported JSON strictly in-memory
    ├── Zero report upload, zero backend API calls, zero analytics
    └── Optional local download: Full or Sanitized (Redacted) JSON / CSV
```

## 2. Scanner Network Behaviour

- **Allowed outbound destinations:** Official AWS SDK service endpoints for the regions you scan (`sts`, `ec2`, `iam`, `lambda`, `rds`, `dynamodb`, `monitoring`, `logs`, `cloudtrail`, plus `s3` only if `--include-s3-checks` is confirmed).
- **Zero telemetry or external services:** No analytics, crash reporters, update-check pings, or AWS Clarity backend URLs exist in the CLI.
- **Zero credential leakage:** Credentials are never logged, printed to stdout/stderr, or written to output reports.

## 3. Browser & Static Website Protections

- **Content Security Policy (Production Build):** `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`.
- **Untrusted JSON Import Hardening (`reportImporter.js`):**
  - Enforces a 25 MB file-size cap.
  - Strips `__proto__`, `constructor`, and `prototype` keys to prevent prototype pollution.
  - Blocks accidental import of files containing AWS credential keys (`SecretAccessKey`, `SessionToken`, `aws_secret_access_key`).
  - Blocks demo fixtures (`is_demo: true`) from mixing with real assessments.
  - Strips control characters and renders all metadata as escaped React text (never `dangerouslySetInnerHTML`, never `eval`).
- **In-Memory Processing:** Imported customer reports are kept in React memory only and cleared when the tab closes or when you click **Clear Current Assessment** in Trust & Privacy Centre.

## 4. Safe Sanitized Sharing

Before exporting, AWS Clarity displays a privacy reminder that full reports contain AWS Account IDs, Resource ARNs, Resource Names, Network Configuration, Public IP addresses, and IAM metadata. Use **Download Sanitized JSON** or **Download Sanitized CSV** to redact identifiers before sharing.

## 5. Honest Security Limitations

- Local-first eliminates vendor backend compromise as a vector for exposing customer AWS accounts.
- It does **not** protect against a compromised workstation, malicious dependency/supply-chain updates, or insecure sharing of unredacted reports.
- Always pin/verify versions and check `SHA256SUMS.txt` against public source code.
