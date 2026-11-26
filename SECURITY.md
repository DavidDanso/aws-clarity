# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability or privacy issue in AWS Clarity (the local Python CLI scanner, the static web report viewer, or build/release workflows), please report it **privately** rather than opening a public GitHub issue or pull request:

- **GitHub Private Security Advisories:** https://github.com/DavidDanso/aws-clarity/security/advisories/new

Please include:
1. Affected component (`aws-clarity` CLI, static web viewer, CloudFormation template, or dependency).
2. Steps to reproduce or proof-of-concept (please use synthetic/redacted data—never send real AWS credentials or private reports).
3. Potential impact (e.g., unintended network call, XSS/HTML injection, credential leakage, or false-negative security check).

> **Maintainer response note:** AWS Clarity is an independent, solo-maintained open-source project. Security reports are reviewed on a best-effort basis; there is no guaranteed response-time SLA or formal enterprise support commitment.

## Security Architecture & Independent Audit

- **10-Minute Independent Audit Guide:** [docs/AUDIT.md](./docs/AUDIT.md)
- **Unknown-Environment Threat Model:** [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md)
- **Privacy & Network Architecture:** [docs/SECURITY_AND_PRIVACY.md](./docs/SECURITY_AND_PRIVACY.md)

AWS Clarity is designed around a **local-first** model:
- The scanner runs locally on the user's workstation using their existing AWS CLI / IAM Identity Center credentials and enforces a client-layer read-only API allowlist (`backend/api_guard.py`).
- AWS Clarity does not operate a central scanning backend, does not assume cross-account roles into customer accounts, and does not store customer inventories.
- The static web dashboard parses imported `.json` reports strictly in browser memory and enforces `Content-Security-Policy: connect-src 'none'` on production builds.

## Security Assurance and Limitations

AWS Clarity has undergone extensive project-maintainer-led security hardening, automated testing, and release verification. However, it has **not** undergone an independent third-party penetration test or received a formal security certification.

AWS Clarity provides visibility and assessment of supported AWS configurations. It does not guarantee that an AWS account is secure, replace AWS security services, or substitute for an independent professional security assessment. Users should independently validate important findings and carefully review remediation guidance before making changes to their AWS environments.

**Operational boundaries:**
- Local-first eliminates central backend credential exposure and central customer database compromises.
- It does **not** eliminate workstation compromise, malicious supply-chain updates, overly broad local credentials, or careless sharing of unredacted report files.

## Verifying Releases, Checksums & Build Provenance

1. **SHA-256 checksums** verify that your downloaded file was not corrupted or altered relative to the release's `SHA256SUMS.txt` file:
   ```bash
   shasum -a 256 -c SHA256SUMS.txt
   ```
   *(Important: A checksum downloaded from the same location as the artifact is **not** a cryptographic publisher signature—if a release page were compromised, an attacker could replace both the artifact and `SHA256SUMS.txt`.)*
2. **GitHub Actions Build Provenance Attestations** (for releases published with `ci-release.yml` v1.1.0+) cryptographically link a downloaded artifact back to the exact GitHub Actions workflow run and commit in `DavidDanso/aws-clarity`:
   ```bash
   gh attestation verify aws_clarity-<version>-py3-none-any.whl --repo DavidDanso/aws-clarity
   ```
3. You can also audit the public source at the matching git tag and build locally from source with `pip install .`.
