# AWS Clarity — Phase 6 Remediation Report

**Branch:** `hardening/unknown-env-beta-readiness`  
**Base commit before remediation:** `36d112855b19bae6daf3a72905e09c6bcbd67647`  
**Target release:** `v1.1.0` (`aws-clarity` `1.1.0`, pending owner-controlled publication)  
**Remediation date:** 2026-11-26

---

## 1. Original Phase 6 Audit Findings & Root Causes

| ID | Area | Original Finding | Root Cause |
| --- | --- | --- | --- |
| **A1** | Accessibility (WCAG 2 AA) | `.bg-teal-600` button with white text (`Choose Local Report File`) failed WCAG AA normal-text contrast (`3.74:1`, required `>= 4.5:1`). | White text (`#ffffff`) on Tailwind `teal-600` (`#0d9488`) falls below `4.5:1`. |
| **A2** | Accessibility (WCAG 2 AA) | `.text-slate-500` muted labels across Setup, Dashboard, ResourceTable, DetailDrawer, and modals failed WCAG AA contrast on dark `slate-900`/`slate-950` backgrounds (`4.06:1–4.23:1`, required `>= 4.5:1`). | Tailwind `slate-500` (`#64748b`) is too dim against `#020617`/`#0f172a` surfaces. |
| **A3** | Accessibility (Keyboard / WCAG 2 AA) | `axe-core` flagged `scrollable-region-focusable` on scrollable modal bodies (`CoverageModal`, `ChecksCatalogModal`, `ScoreModal`). Mobile 375px testing also identified 4 horizontal `<pre>` command blocks in `SetupScreen.jsx`. | Scrollable `overflow-y-auto` / `overflow-x-auto` containers without focusable descendants lacked `tabIndex={0}` (and landmark `role="region"` + `aria-label` on modal bodies). |
| **B** | Backend / Botocore | `backend/utils.py:46` emitted `DeprecationWarning` from `_SHARED_STATIC_BC.get_component("endpoint_resolver")` under strict `-W error::DeprecationWarning`. | Legacy Lambda cold-start optimization accessed a deprecated internal `botocore` session hook (`get_component("endpoint_resolver")`) instead of the supported public `boto3.Session(...)` API. |
| **C** | Packaging / Setuptools | `python -m build` with `setuptools 84.2.1` emitted 3 PEP 639 deprecation warnings (`project.license = { text = "MIT" }`, `tool.setuptools.license-files`, `License :: OSI Approved :: MIT License` classifier; deadline `2027-Feb-18`). | `pyproject.toml` pins `requires = ["setuptools>=68.0"]` for broad Python 3.10–3.13 build compatibility. |
| **D** | Release & Install Docs | `v1.1.0` package is not yet published; intended `v1.1.0` URLs and platform install commands needed to be prepared cleanly without dead links or `/releases/latest`. | `v1.0.0` predates hardening and `v1.1.0` tag has not yet been pushed. |
| **E** | Public Repo Exposure | Confirm actual repo visibility and scan tracked files, full Git history, and release archives for credentials/secrets (including the owner-supplied candidate AKIA-like identifier). | Independent preflight required before wider sharing. |

---

## 2. Changes Made

### Task A — Accessibility Fixes
- **A1 (`frontend/src/pages/SetupScreen.jsx`):** Updated the `"Choose Local Report File"` primary dropzone button from `bg-teal-600 hover:bg-teal-500 text-white` (`3.74:1`) to `bg-teal-500 hover:bg-teal-400 active:bg-teal-300 text-slate-950 font-bold` (`#020617` on `#14b8a6`, matching the hero CTA with `> 9:1` contrast, preserving hover/active/focus-visible states).
- **A2 (10 frontend files):** Upgraded all `.text-slate-500` text elements to `.text-slate-400` (`#94a3b8` on `#0f172a` ≈ `6.2:1`, on `#020617` ≈ `7.1:1`) across `App.jsx`, `TopBar.jsx`, `SetupScreen.jsx`, `DashboardScreen.jsx`, `ResourceTable.jsx`, `DetailDrawer.jsx`, `CoverageModal.jsx`, `ChecksCatalogModal.jsx`, `ScoreModal.jsx`, and `TrustModal.jsx`. Replaced decorative `.text-slate-600` middots/ellipses (`DetailDrawer.jsx`, `ResourceTable.jsx`) with `text-slate-400` + `aria-hidden="true"`. Zero `.text-slate-500` or `.bg-teal-600` classes remain anywhere in `frontend/src/`.
- **A3 (Scrollable Modals & Mobile Code Blocks):**
  - Added `tabIndex={0} role="region" aria-label="..."` to scrollable bodies in `CoverageModal.jsx` (main body + failures list), `ChecksCatalogModal.jsx`, `ScoreModal.jsx`, `TrustModal.jsx` (main body + policy JSON `<pre>`), and `DetailDrawer.jsx` (raw attributes panel).
  - Added `tabIndex={0}` to the 5 horizontally scrollable `<pre>` command/policy blocks in `SetupScreen.jsx` after mobile 375px `axe-core` flagged horizontal overflow scroll accessibility on narrow screens.

### Task B — Botocore Deprecation Removal (`backend/utils.py`)
- Removed `import botocore.session`, `_SHARED_STATIC_BC`, `_SHARED_DATA_LOADER`, and `_SHARED_ENDPOINT_RESOLVER` (`get_component("endpoint_resolver")`).
- Replaced `build_isolated_session(...)` with the supported public API: `boto3.Session(aws_access_key_id=..., aws_secret_access_key=..., aws_session_token=..., region_name=...)`.
- No warnings suppressed or filtered; no scanner behavior, region handling, or IAM permissions changed.

### Task C — Setuptools PEP 639 Warning Decision
- **Decision: Keep `requires = ["setuptools>=68.0"]` unchanged for `v1.1.0` and schedule PEP 639 migration as a post-`v1.1.0` maintenance item prior to `2027-02-18`.**
- **Rationale:**
  1. Python 3.10 ships with `pip 22.2.1` and many enterprise/Linux environments still carry `setuptools 68.x–76.x` for `--no-build-isolation` builds; raising the build-system floor to `setuptools>=77.0.0` right before `v1.1.0` adds unnecessary packaging churn.
  2. Current `v1.1.0` wheel and sdist builds pass `twine check --strict` (`PASSED`), include `LICENSE`, preserve the MIT license, and install cleanly in isolated virtual environments.
  3. **Honesty note:** The 3 build-time `SetuptoolsDeprecationWarning` notices (`project.license`, `tool.setuptools.license-files`, and the MIT license classifier) remain present during `python -m build` with `setuptools 84.2.1` and have **not** been resolved in `v1.1.0`. Target migration deadline: **before 2027-02-18** (recommended in `v1.1.1` / `v1.2.0` once `setuptools>=77.0.0` + `pip>=24` baseline is adopted).

### Task D & G — Documentation & Release Preparation
- Updated [`docs/GETTING_STARTED.md`](./GETTING_STARTED.md) with prepared intended `v1.1.0` URLs (clearly marked pending publication) and `aws-clarity --help` / `aws-clarity scan --help` checks.
- Added [`docs/V1.1.0_INSTALLATION_PREPARATION.md`](./V1.1.0_INSTALLATION_PREPARATION.md), [`docs/REPOSITORY_EXPOSURE_PREFLIGHT.md`](./REPOSITORY_EXPOSURE_PREFLIGHT.md), [`docs/RELEASE_NEXT_STEPS.md`](./RELEASE_NEXT_STEPS.md), and this report.

---

## 3. Regression Tests Added

Added [`backend/test_phase6_remediation.py`](../backend/test_phase6_remediation.py) (5 new tests, bringing the backend suite from 67 → **72 tests**):
1. `test_utils_does_not_call_deprecated_internal_endpoint_resolver` — AST check verifying `backend/utils.py` never calls `get_component()` or references `_SHARED_STATIC_BC` / `_SHARED_ENDPOINT_RESOLVER`.
2. `test_build_isolated_session_emits_no_deprecation_warnings` — executes `utils.build_isolated_session(...)` under `warnings.simplefilter("always", DeprecationWarning)` and verifies zero `DeprecationWarning`s plus strict credential/region isolation across two sessions.
3. `test_frontend_and_docs_match_pyproject_version_and_artifacts` — **version & URL parity guard** reading `[project].name` and `[project].version` from `pyproject.toml` and asserting exact agreement across `SetupScreen.jsx`, `docs/GETTING_STARTED.md`, and `docs/V1.1.0_INSTALLATION_PREPARATION.md` (and prohibiting `/releases/latest` URLs, PyPI URLs, or clickable dead `v1.1.0` links in `SetupScreen.jsx`).
4. `test_no_low_contrast_slate_500_or_teal_600_regressions` — scans every `frontend/src/**/*.jsx` file to prevent reintroduction of `.text-slate-500` or `.bg-teal-600`.
5. `test_scrollable_modals_have_keyboard_focusable_regions` — verifies `CoverageModal`, `ChecksCatalogModal`, `ScoreModal`, and `TrustModal` retain `tabIndex={0}` and `role="region"`.

---

## 4. Actual Verification Results

### Backend (72 tests, non-interactive stdin `< /dev/null`)
- **Python 3.10.6** (`-W error::DeprecationWarning`): **72/72 PASS** (0 warnings).
- **Python 3.11.4** (`-W error::DeprecationWarning`): **72/72 PASS** (0 warnings).
- **Python 3.12.4 clean venv** (`boto3==1.42.66`, `botocore==1.42.66`, `python-dateutil==2.9.0.post0`, `-W error::DeprecationWarning`): **72/72 PASS** (0 warnings).
  - *Transparency note on system Python 3.12:* The host's global `/Library/Frameworks/Python.framework/Versions/3.12` has an older third-party `python-dateutil==2.8.2` (`dateutil/tz/tz.py:37` calls `datetime.datetime.utcfromtimestamp(0)`), which triggers a third-party `DeprecationWarning` under `-W error::DeprecationWarning` during `botocore.compat` import before any AWS Clarity code runs. Standard mode on system Python 3.12 passed **72/72**, and clean venv Python 3.12 with the package's real dependencies (`boto3==1.42.66` + `python-dateutil==2.9.0.post0`) passed **72/72** with `-W error::DeprecationWarning`.
- **Python 3.13.3** (`boto3==1.42.66`, `-W error::DeprecationWarning`): **72/72 PASS** (0 warnings).

### Frontend & Accessibility
- **ESLint (`--max-warnings 0`):** PASS (0 errors, 0 warnings).
- **Vite Production Build:** PASS (`dist/assets/index-BoE2uyUw.js`, `dist/assets/index-DrL4jrrI.css`).
- **Static Suites (`verify-frontend-invariants`, `verify-phase1-canary`, `verify-phase2-correctness`, `verify-phase3-security`, `verify-phase5-ux`):** ALL PASS.
- **Headless Chrome Security & UX Suites (`verify-phase3-browser`, `verify-phase5-browser`):** ALL PASS (CSP enforcement, offline report import, zero outbound requests, 320px–1440px responsive layout, reduced motion, keyboard Escape/focus return).
- **`axe-core` WCAG 2 A/AA/2.1AA + best-practice (unmodified rules, zero suppressions):** **0 violations across ALL 9 audited views**:
  - `SetupScreen` (1280×800): **0 violations** (136 contrast passes, 0 contrast fails)
  - `SetupScreen` (Mobile 375×812): **0 violations** (133 contrast passes, 0 contrast fails; 0px horizontal overflow)
  - `TrustModal`: **0 violations** (167 contrast passes); Tab + PageDown scroll verified (`0 -> 131`)
  - `DashboardScreen (Demo)`: **0 violations** (196 contrast passes)
  - `CoverageModal`: **0 violations** (245 contrast passes); Tab + PageDown scroll verified (`0 -> 73`)
  - `ChecksCatalogModal`: **0 violations** (244 contrast passes); Tab + PageDown scroll verified (`0 -> 49`)
  - `DetailDrawer`: **0 violations** (195 contrast passes)
  - `ScoreModal`: **0 violations** (75 contrast passes); Tab + PageDown scroll verified (`0 -> 70`)
  - `ExportModal`: **0 violations** (64 contrast passes)
- **Viewport overflow check (`320px`, `375px`, `390px`, `768px`):** `0px` horizontal overflow.

### Packaging (`v1.1.0` Fresh Local Build)
- Built via `bash scripts/build-release-artifacts.sh`:
  - `aws_clarity-1.1.0-py3-none-any.whl` (`2557edc4893103b19671bf31a9aa19fa9da6cad33fcaf41a36fe7a3a40a35803`)
  - `aws_clarity-1.1.0.tar.gz` (`fa76c09ba6f6917545572b8349199f076352a3eb370da02a6c918ef2a5ad4858`)
  - `aws-clarity-local-1.1.0.tar.gz` (`ed584aac5508526e07758f13d0893933f5207023f8f117a9d0157048b884cdde`)
- `shasum -a 256 -c SHA256SUMS.txt`: **ALL OK**.
- `twine check --strict`: **PASSED** on both wheel and sdist.
- Content audit: `api_guard.py`, `LICENSE`, `aws_clarity_cli.py`, and updated `utils.py` (zero `get_component()` calls) verified inside wheel/sdist/tarball; zero secrets or local paths.
- Clean isolated venv install (`/tmp/p6-clean-venv`):
  - `aws-clarity version` → `aws-clarity 1.1.0 (local-first, read-only, zero telemetry)`
  - `aws-clarity --help` & `aws-clarity scan --help` (`--yes`, `--allow-root`, `--include-s3-checks`, `--confirm-s3-request-costs`) → PASS
  - `aws-clarity policy --zero-cost-only` → **28 actions**; `aws-clarity policy` → **34 actions**
  - Root identity refusal without `--allow-root` → exit code `2` (`ROOT_BLOCK_IN_WHEEL: OK`)
  - Explicit `--allow-root --yes` override → exit code `0` (`WHEEL_ALLOW_ROOT_AND_YES: OK`)

---

## 5. Outstanding Defects / Unverified Items & Owner Actions

- **No open Phase 6 code or accessibility defects remain.**
- **Unverified locally (`NOT VERIFIED`):**
  - `gitleaks` / `trufflehog` / `detect-secrets` (not installed locally; full-history Python regex + SHA-256 scan passed across all 114 commits and 99 tracked files).
  - Final GitHub Actions 12-job matrix CI on the remediated commit (awaits owner-approved branch push).
  - Live `v1.1.0` GitHub Release URLs, live deployed hardened website, and live CloudFront HTTP security headers (await owner-controlled merge, tag, and deploy).
- **Scheduled maintenance (non-blocking for `v1.1.0`):** Migrate `pyproject.toml` to PEP 639 (`license = "MIT"`, `project.license-files = ["LICENSE"]`, `setuptools>=77.0.0`) before **2027-02-18**.
- **Owner actions required:** See [`docs/RELEASE_NEXT_STEPS.md`](./RELEASE_NEXT_STEPS.md) and [`docs/REPOSITORY_EXPOSURE_PREFLIGHT.md`](./REPOSITORY_EXPOSURE_PREFLIGHT.md).
