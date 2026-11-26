# Getting Started & Local Scanner Installation

AWS Clarity runs **locally on your computer** using your existing AWS CLI or IAM Identity Center (AWS SSO) credentials. Your AWS credentials and account inventory never leave your environment.

> **Published release (`v1.1.0`):** The hardened **`v1.1.0`** scanner package (`aws-clarity` `1.1.0` — `aws_clarity-1.1.0-py3-none-any.whl`, `aws_clarity-1.1.0.tar.gz`, `aws-clarity-local-1.1.0.tar.gz`, `SHA256SUMS.txt` with GitHub Actions SLSA build provenance) is published on [GitHub Releases (`v1.1.0`)](https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0). Avoid the older `v1.0.0` release, which predates the read-only API allowlist, root-account block, and pre-scan confirmation. (`aws-clarity` is distributed via GitHub Releases and source checkout, not PyPI.)

### Published `v1.1.0` Release Assets

- **Release Page:** https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0
- **Wheel Asset:** https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws_clarity-1.1.0-py3-none-any.whl
- **Source Distribution:** https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws_clarity-1.1.0.tar.gz
- **Standalone Source Tarball:** https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws-clarity-local-1.1.0.tar.gz
- **SHA-256 Manifest:** https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/SHA256SUMS.txt

## Prerequisites

- **Python 3.10+** (macOS, Linux, or Windows)
- **AWS CLI v2** configured with a profile or IAM Identity Center (`aws sso login`)
- **Recommended:** a dedicated read-only IAM role or IAM Identity Center permission set (see [IAM Permissions](./IAM_PERMISSIONS.md) and `infra/aws-clarity-readonly-role.yaml`)

## 1. Install the Local Scanner

### Option A — `pipx` (Recommended)

```bash
git clone https://github.com/DavidDanso/aws-clarity.git
cd aws-clarity
pipx install .
```

*(After downloading and verifying `aws_clarity-1.1.0-py3-none-any.whl` from GitHub Release `v1.1.0`: `pipx install ./aws_clarity-1.1.0-py3-none-any.whl`.)*

### Option B — macOS / Linux Virtual Environment (`venv` + `pip`)

```bash
git clone https://github.com/DavidDanso/aws-clarity.git
cd aws-clarity
python3 -m venv ~/.aws-clarity
~/.aws-clarity/bin/pip install .
```

### Option C — Windows PowerShell Virtual Environment

```powershell
git clone https://github.com/DavidDanso/aws-clarity.git
cd aws-clarity
py -m venv "$HOME\.aws-clarity"
& "$HOME\.aws-clarity\Scripts\pip.exe" install .
```

Verify installation and CLI help:

```bash
aws-clarity version
# Expected: aws-clarity 1.1.0 (local-first, read-only, zero telemetry)

aws-clarity --help
aws-clarity scan --help
```

### Verify Before Installing (`v1.1.0`)

Before installing a downloaded release file (`aws_clarity-1.1.0-py3-none-any.whl`), verify its SHA-256 checksum against `SHA256SUMS.txt`:

- **macOS:**
  ```bash
  shasum -a 256 -c SHA256SUMS.txt
  ```
- **Linux:**
  ```bash
  sha256sum -c SHA256SUMS.txt
  ```
- **Windows (PowerShell):**
  ```powershell
  (Get-FileHash .\aws_clarity-1.1.0-py3-none-any.whl -Algorithm SHA256).Hash.ToLower()
  ```
  Compare the 64-character hex digest printed by PowerShell against the `aws_clarity-1.1.0-py3-none-any.whl` entry in `SHA256SUMS.txt`.

> **Checksum vs. signature:** A SHA-256 checksum verifies download integrity against the release manifest—it is **not** a cryptographic digital signature. Once `v1.1.0` is published via GitHub Actions, you can also verify SLSA build provenance with `gh attestation verify aws_clarity-1.1.0-py3-none-any.whl --repo DavidDanso/aws-clarity`.

## 2. Authenticate With a Dedicated Read-Only AWS Identity

AWS Clarity uses the standard AWS SDK (`boto3`) credential provider chain. Avoid using AWS account root credentials (refused by default) or `AdministratorAccess`. Note that a role is not automatically safe simply because its name contains `ReadOnly`, and AWS Clarity cannot prove your identity's complete effective IAM permissions.

```bash
# If using IAM Identity Center (AWS SSO):
aws sso login --profile my-readonly-profile

# Confirm which AWS account you are targeting before scanning:
aws sts get-caller-identity --profile my-readonly-profile
```

## 3. Check Permissions Locally (`doctor`)

Run `doctor` first to probe enabled regions and read-only permissions:

```bash
aws-clarity doctor --profile my-readonly-profile
```

Optional: also probe S3 permissions if you intend to opt into S3 checks:

```bash
aws-clarity doctor --profile my-readonly-profile --include-s3-checks
```

## 4. Run a Local Read-Only Assessment (`scan`)

Default scan (**9 zero-request-charge control-plane services**, S3 intentionally skipped as `SKIPPED_OPTIONAL`):

```bash
aws-clarity scan --profile my-readonly-profile --output aws-clarity-report.json
```

Before calling any service collector, `aws-clarity scan` displays a pre-scan confirmation showing your masked account ID, masked caller ARN, credential source, target regions, service scope, what is collected vs. deliberately not collected, and potential AWS API fees. Confirm interactively (`y`) or pass `--yes` in non-interactive shells after reviewing scope.

Optional: include S3 bucket configuration checks (displays AWS S3 request pricing and requires explicit consent):

```bash
aws-clarity scan --profile my-readonly-profile --include-s3-checks --output aws-clarity-report.json
```

For non-interactive automation after reviewing scope and S3 request pricing:

```bash
aws-clarity scan --profile my-readonly-profile --yes --include-s3-checks --confirm-s3-request-costs --output aws-clarity-report.json
```

Using a customer-owned read-only IAM role from your local profile (no AWS Clarity AWS account involved):

```bash
aws-clarity scan --profile my-profile --role-arn arn:aws:iam::123456789012:role/AWSClarityReadOnlyRole --output aws-clarity-report.json
```

Reports are saved locally with owner-only `0600` file permissions on macOS/Linux (POSIX); on Windows, standard user directory ACLs apply. Reports never contain AWS credentials.

## 5. View & Compare Reports Offline in Your Browser

You can turn off your Wi-Fi before dropping your report file. It works the same.

1. Open the AWS Clarity dashboard (locally via `cd frontend && npm run dev`, or the deployed static site once updated).
2. Click **Choose Local Report File** (or drag and drop `aws-clarity-report.json`).
3. Reports stay strictly in browser memory (never uploaded, never automatically saved in browser storage; closing the tab clears active state).
4. After applying manual fixes in AWS, run `aws-clarity scan` again and click **Compare Scan** in the dashboard to review verified **Resolved**, **Unverified**, **New**, and **Unchanged** findings locally in memory.

## Team Usage & Sharing

- Individual engineers and teams can run `aws-clarity scan` locally using their own authorized AWS CLI / IAM Identity Center profiles.
- Use **Export → Download Sanitized JSON** (or **Download Sanitized CSV**) when sharing findings. Sanitized exports use best-effort redaction and are **not** guaranteed to be completely anonymous—always inspect the file before sharing. Full exports contain sensitive infrastructure identifiers and should remain private.
- AWS Clarity v1 intentionally does **not** include user login, shared team databases, multi-account org dashboards, or automatic remediation.
