/**
 * Phase 5: Usability, Onboarding, Accessibility & Documentation Verification Suite
 *
 * Verifies:
 * - First-five-seconds plain-English landing answers
 * - Honest unpublished v1.1.0 release notice (no silent v1.0.0 install fallback, no invented v1.1.0 URLs)
 * - Verify Before Installing checksum commands (macOS, Linux, PowerShell) + checksum != digital signature note
 * - Step 2 read-only role recommendation + ReadOnly role-name honesty
 * - Step 3 exact offline Wi-Fi guarantee
 * - Production account safety FAQ exact title & balanced disclosures
 * - Accessibility & reduced-motion patterns in CSS and components
 * - Documentation Known Limitations completeness across README.md and docs/
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendRoot, "..");

const setupSrc = fs.readFileSync(path.join(frontendRoot, "src", "pages", "SetupScreen.jsx"), "utf8");
const setupFlat = setupSrc.replace(/\s+/g, " ");
const dashSrc = fs.readFileSync(path.join(frontendRoot, "src", "pages", "DashboardScreen.jsx"), "utf8");
const cssSrc = fs.readFileSync(path.join(frontendRoot, "src", "index.css"), "utf8");
const appSrc = fs.readFileSync(path.join(frontendRoot, "src", "App.jsx"), "utf8");

// 1. Unpublished v1.1.0 honesty: must NOT direct users to download v1.0.0 wheel or invented v1.1.0 download URL
assert.ok(
  !setupSrc.includes("releases/download/v1.0.0"),
  "SetupScreen must not instruct visitors to install outdated v1.0.0 as hardened"
);
assert.ok(
  !setupSrc.includes("releases/download/v1.1.0"),
  "SetupScreen must not invent working download links for unpublished v1.1.0 artifacts"
);
assert.ok(setupSrc.includes("not yet published"), "SetupScreen must clearly note v1.1.0 is not yet published");
assert.ok(setupSrc.includes("aws_clarity-${PROPOSED_VERSION}-py3-none-any.whl"));

// 2. Verify Before Installing commands & checksum vs signature clarity
assert.ok(setupSrc.includes("Verify Before Installing"));
assert.ok(setupSrc.includes("shasum -a 256 -c SHA256SUMS.txt"));
assert.ok(setupSrc.includes("sha256sum -c SHA256SUMS.txt"));
assert.ok(setupSrc.includes("Get-FileHash"));
assert.ok(setupSrc.includes("digital signature"));

// 3. Step 2 honesty + Step 3 exact offline Wi-Fi sentence + Production Account FAQ
assert.ok(setupSrc.includes("Recommended: use a dedicated read-only role first"));
assert.ok(setupSrc.includes("ReadOnly"));
assert.ok(setupSrc.includes("complete effective IAM permissions"));
assert.ok(
  setupFlat.includes("You can turn off your Wi-Fi before dropping your report file. It works the same."),
  "Step 3 must include the exact offline Wi-Fi guarantee sentence"
);
assert.ok(
  setupSrc.includes("Can I use AWS Clarity with a production AWS account?"),
  "FAQ must include exact production account safety question"
);

// 4. Accessibility & reduced-motion patterns
assert.ok(cssSrc.includes(":focus-visible"), "Global :focus-visible outline must be defined");
assert.ok(cssSrc.includes("prefers-reduced-motion: no-preference"), "Motion should opt-in with prefers-reduced-motion: no-preference");
assert.ok(cssSrc.includes("pointer: coarse"), "Coarse pointer touch targets (44px) must be configured");
assert.ok(!cssSrc.includes("overflow-x: clip"), "Avoid overflow-x: clip on html/body per responsive layout guidance");
assert.ok(setupSrc.includes("skip-link") && setupSrc.includes("<main"), "SetupScreen must have skip link and <main> landmark");
assert.ok(dashSrc.includes("skip-link") && dashSrc.includes("<main"), "DashboardScreen must have skip link and <main> landmark");
assert.ok(dashSrc.includes("useDialogFocus"), "DashboardScreen export dialog must use focus management");
assert.ok(appSrc.includes("document.title"), "App must update document.title on view transitions");

// 5. Known Limitations documentation checks
const readme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
const rulesDoc = fs.readFileSync(path.join(repoRoot, "docs", "SUPPORTED_SERVICES_AND_RULES.md"), "utf8");
const troubleDoc = fs.readFileSync(path.join(repoRoot, "docs", "TROUBLESHOOTING.md"), "utf8");

assert.ok(readme.includes("## Known Limitations (v1)"), "README.md must include a visible Known Limitations section");
for (const topic of [
  "customer-managed policy",
  "permission boundaries",
  "IAM groups",
  "account-level S3 Public Access Block",
  "Organizations",
  "CloudTrail Lake",
  "90-second",
  "INFO",
  "S3 Free Tier",
  "security certification",
  "penetration test",
]) {
  assert.ok(
    rulesDoc.toLowerCase().includes(topic.toLowerCase()),
    `docs/SUPPORTED_SERVICES_AND_RULES.md Known Limitations missing topic: ${topic}`
  );
}
assert.ok(troubleDoc.includes("Python 3.10+ Is Missing") && troubleDoc.includes("pipx"));

console.log("All Phase 5 usability, onboarding, accessibility, and documentation static checks passed.");
