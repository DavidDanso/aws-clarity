# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability or privacy issue in AWS Clarity (the local Python CLI scanner, the static web report viewer, or build/release scripts), please report it privately rather than opening a public issue:

- **GitHub Security Advisories:** https://github.com/DavidDanso/aws-clarity/security/advisories/new

Please include:
1. Affected component (`aws-clarity` CLI, static web viewer, or dependency).
2. Steps to reproduce or proof-of-concept.
3. Potential impact (e.g., unintended network call, XSS/HTML injection, credential leakage, or false-negative security check).

## Security Architecture & Honest Boundaries

AWS Clarity is designed around a **local-first** model:
- The scanner runs locally on the user's workstation using their existing AWS CLI / IAM Identity Center credentials.
- AWS Clarity does not operate a central scanning backend, does not assume cross-account roles into customer accounts, and does not store customer inventories.
- The static web dashboard parses imported `.json` reports strictly in browser memory and enforces `Content-Security-Policy: connect-src 'none'` on production builds.

**What this does and does not guarantee:**
- Local-first eliminates central backend credential exposure and central customer database compromises.
- It does **not** make breaches impossible: compromised workstations, malicious software supply-chain updates, or careless sharing of unredacted report files remain real risks.
- AWS Clarity is an independent open-source project and has **not** undergone third-party penetration testing or SOC 2 / ISO 27001 certification.

## Verifying Releases & Checksums

Before installing a release archive, verify its SHA-256 checksum against the matching tagged source release:

```bash
shasum -a 256 -c SHA256SUMS.txt
```
