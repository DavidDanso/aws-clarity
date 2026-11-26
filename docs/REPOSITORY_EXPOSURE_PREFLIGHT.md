# Public Repository Exposure Preflight

**Repository:** `https://github.com/DavidDanso/aws-clarity`  
**Branch audited:** `hardening/unknown-env-beta-readiness` (plus all refs/tags in local Git object store)  
**Audit date:** 2026-11-26

---

## 1. Actual GitHub Repository Visibility

Confirmed via unauthenticated HTTP request (`GET https://api.github.com/repos/DavidDanso/aws-clarity`):

- **HTTP status:** `200 OK`
- **`private`:** `false`
- **`visibility`:** `public`
- **`default_branch`:** `main`
- **`security_and_analysis` (unauthenticated response):** `null` (repository security settings such as Private Vulnerability Reporting and Secret Scanning cannot be verified without authenticated admin access)
- **Release tags checked unauthenticated:**
  - `https://github.com/DavidDanso/aws-clarity/releases/tag/v1.0.0` → `HTTP 200` (already publicly downloadable)
  - `https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0` → `HTTP 404` (not yet published)

**Conclusion:** The repository is **already public** today.

---

## 2. Scope Inspected

| Scope | Coverage |
| --- | --- |
| Current tracked files (`git ls-files`) | All **99 tracked files** (backend Python, tests, frontend React/Vite/scripts, Terraform `infra/`, GitHub workflows, `docs/`, `scripts/`, packaging metadata) |
| Full Git commit history (`git rev-list --all`) | All **114 commits** across `main`, `hardening/unknown-env-beta-readiness`, and `v1.0.0` tag (including deleted/renamed historical paths and commit patches) |
| Published `v1.0.0` release archives | `aws_clarity-1.0.0-py3-none-any.whl`, `aws_clarity-1.0.0.tar.gz`, `aws-clarity-local-1.0.0.tar.gz` |
| Rebuilt local `v1.1.0` release archives | `aws_clarity-1.1.0-py3-none-any.whl`, `aws_clarity-1.1.0.tar.gz`, `aws-clarity-local-1.1.0.tar.gz` |

---

## 3. Preflight Status Summary

| Check | Status | Tool / Method | Findings |
| --- | --- | --- | --- |
| Public repository visibility check | **PASS** | Unauthenticated `curl` to GitHub REST API | Confirmed `visibility: public`, `private: false`. |
| Candidate AWS key identifier search (supplied by owner) | **PASS** | Python full-history SHA-256 matcher over all 99 tracked files, all 114 commits, `v1.0.0` assets, and `v1.1.0` assets | **0 matches** in tracked files, full Git history, or release archives. *(Candidate value never printed in logs or reports.)* |
| General AWS access key (`AKIA`/`ASIA`) scan | **PASS** | Python regex scan over all 99 tracked files, all 114 commits, and `v1.0.0`/`v1.1.0` archives | **0 non-synthetic keys** found. Only synthetic test fixtures containing `EXAMPLE` / test placeholders (`test_local_cli.py`, `test_phase1_hardening.py`, `test_phase6_remediation.py`). |
| GitHub tokens, private keys, passwords, session tokens | **PASS** | Python regex scan (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, PEM private keys, `AWS_SECRET_ACCESS_KEY`) | **0 findings** across all files, commits, and release packages. |
| Real customer reports, `.env`, `.tfstate`, debug logs | **PASS** | Filename & content scan across all 99 tracked files and all 114 historical commits | **0 sensitive files** found (no `.env`, `.tfstate`, `.pem`, `.key`, or real `aws-clarity-report.json` committed). |
| Personal local file paths (`/Users/...`, `/home/...`, `C:\Users\...`) | **PASS** | Python regex scan across tracked files, full Git history, and `v1.0.0`/`v1.1.0` packages | **0 personal local paths** found. |
| Sensitive AWS account IDs | **PASS** | 12-digit account ID pattern audit across tracked files and tests | Only synthetic placeholder account IDs (`123456789012`, `111122223333`, `999988887777`, `777777777777`, `000000000000`) used in unit tests, examples, and demo fixtures. |
| `gitleaks` / `trufflehog` / `detect-secrets` dedicated scanner | **NOT VERIFIED** | Checked via `which gitleaks trufflehog detect-secrets` | None of these dedicated third-party secret scanners are installed in the local environment. Reported explicitly as `NOT VERIFIED`. |
| Owner IAM key hygiene & GitHub security settings | **OWNER ACTION REQUIRED** | Out-of-band AWS IAM / GitHub admin settings | See Section 4 below. |

---

## 4. Owner Actions Required

1. **Run a dedicated secret scanner (`gitleaks`) or enable GitHub Secret Scanning + Push Protection:**
   - Because `gitleaks`, `trufflehog`, and `detect-secrets` were not installed locally, that layer is currently `NOT VERIFIED`.
   - Recommended command on a machine with `gitleaks` installed:
     ```bash
     gitleaks detect --source . --verbose --redact
     ```
   - In GitHub repository **Settings → Code security**, confirm **Secret scanning** and **Push protection** are enabled on `DavidDanso/aws-clarity`.
2. **Owner-led review of local AWS IAM key hygiene (no compromise assumed):**
   - The user-supplied AKIA-like candidate key identifier was **not** found anywhere in tracked files, Git history (all 114 commits), or `v1.0.0`/`v1.1.0` release assets. Treat that string strictly as a candidate key identifier, not proof of compromise.
   - Independently, as general AWS account hygiene (and given earlier local diagnostics noting a 252-day-old `danso` IAM user access key), the owner should review whether any long-lived IAM user access keys can be rotated or replaced with short-lived IAM Identity Center (AWS SSO) sessions and GitHub Actions OIDC roles. Do not share or paste key values into logs or prompts.
3. **Verify GitHub Private Vulnerability Reporting:**
   - `SECURITY.md` and the frontend Trust & Privacy modal link to `https://github.com/DavidDanso/aws-clarity/security/advisories/new`.
   - Confirm in **Settings → Code security → Private vulnerability reporting** that private advisories are enabled so external security researchers do not encounter a disabled endpoint.
