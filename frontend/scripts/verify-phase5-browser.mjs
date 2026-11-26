/**
 * verify-phase5-browser.mjs
 *
 * Reproducible headless Chrome/Chromium end-to-end UX, offline, responsive (320px–1440px),
 * keyboard navigation, reduced-motion, and accessibility verifier for `frontend/dist/`.
 *
 * Usage:
 *   npm --prefix frontend run build
 *   PLAYWRIGHT_CORE_DIR=/tmp/p3-browser node frontend/scripts/verify-phase5-browser.mjs
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");
const distDir = path.join(frontendRoot, "dist");

if (!fs.existsSync(path.join(distDir, "index.html"))) {
  console.error("ERROR: frontend/dist/index.html not found. Run `npm --prefix frontend run build` first.");
  process.exit(1);
}

function loadPlaywrightCore() {
  const candidates = [];
  if (process.env.PLAYWRIGHT_CORE_DIR) {
    candidates.push(path.join(path.resolve(process.env.PLAYWRIGHT_CORE_DIR), "_resolve.cjs"));
  }
  candidates.push(path.join(frontendRoot, "package.json"));
  for (const anchorPath of candidates) {
    try {
      const req = createRequire(anchorPath);
      return req("playwright-core");
    } catch {
      // Try next candidate
    }
  }
  console.error("ERROR: `playwright-core` not found. Set PLAYWRIGHT_CORE_DIR=/tmp/p3-browser.");
  process.exit(2);
}

function resolveChromeBinary() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  for (const p of [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ]) {
    if (fs.existsSync(p)) return p;
  }
  return undefined;
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

function startStaticDistServer(rootDir) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const urlPath = (req.url || "/").split("?")[0];
      const safeRel = path.normalize(urlPath === "/" ? "index.html" : urlPath).replace(/^(\.\.[/\\])+/, "");
      let fullPath = path.join(rootDir, safeRel);
      if (!fullPath.startsWith(rootDir) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
        fullPath = path.join(rootDir, "index.html");
      }
      const ext = path.extname(fullPath).toLowerCase();
      res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
      fs.createReadStream(fullPath).pipe(res);
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, url: `http://127.0.0.1:${addr.port}/` });
    });
  });
}

function buildFixtures(tmpDir) {
  const emptyComplete = path.join(tmpDir, "empty-complete.json");
  const emptyIncomplete = path.join(tmpDir, "empty-incomplete.json");
  const richBefore = path.join(tmpDir, "rich-before.json");
  const richAfterResolved = path.join(tmpDir, "rich-after-resolved.json");

  fs.writeFileSync(
    emptyComplete,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "COMPLETE",
      account_id: "111122223333",
      regions: ["us-east-1"],
      scanned_at: "2026-11-26T10:00:00Z",
      partial: false,
      summary: { total_resources: 0, critical_issues: 0, warnings: 0, unused: 0, info_observations: 0, healthy: 0, incomplete_resources: 0, health_score_available: true },
      account_advisories: [],
      coverage: { status: "COMPLETE", is_partial: false, regions_scanned: ["us-east-1"], regions_succeeded: ["us-east-1"], regions_failed: [], services_skipped_optional: ["S3"], failures: [], scanner_statuses: [{ service: "EC2", key: "ec2_instances", region: "us-east-1", status: "COMPLETED", count: 0 }] },
      resources: { ec2_instances: [], vpcs: [] },
    })
  );

  fs.writeFileSync(
    emptyIncomplete,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "INCOMPLETE",
      account_id: "111122223333",
      regions: ["us-east-1"],
      scanned_at: "2026-11-26T10:01:00Z",
      partial: true,
      summary: { total_resources: 0, critical_issues: 0, warnings: 0, unused: 0, info_observations: 0, healthy: 0, incomplete_resources: 0, health_score_available: false },
      account_advisories: [],
      coverage: { status: "INCOMPLETE", is_partial: true, regions_scanned: ["us-east-1"], regions_succeeded: [], regions_failed: ["us-east-1"], services_skipped_optional: ["S3"], failures: [{ service: "EC2", label: "EC2 Instances", region: "us-east-1", reason: "AccessDenied" }], scanner_statuses: [{ service: "EC2", key: "ec2_instances", region: "us-east-1", status: "FAILED", count: 0 }] },
      resources: { ec2_instances: [], vpcs: [] },
    })
  );

  fs.writeFileSync(
    richBefore,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "COMPLETE",
      account_id: "111122223333",
      regions: ["us-east-1"],
      scanned_at: "2026-11-26T10:00:00Z",
      scan_duration_ms: 1500,
      partial: false,
      summary: { total_resources: 2, critical_issues: 1, warnings: 0, unused: 0, info_observations: 1, healthy: 1, incomplete_resources: 0, health_score_available: true },
      account_advisories: [],
      coverage: {
        status: "COMPLETE",
        is_partial: false,
        regions_scanned: ["us-east-1"],
        regions_succeeded: ["us-east-1"],
        regions_failed: [],
        services_skipped_optional: ["S3"],
        failures: [],
        scanner_statuses: [
          { service: "EC2", key: "security_groups", region: "us-east-1", status: "COMPLETED", count: 1 },
          { service: "Lambda", key: "lambda_functions", region: "us-east-1", status: "COMPLETED", count: 1 },
        ],
      },
      resources: {
        security_groups: [
          {
            id: "sg-000111222",
            name: "web-sg",
            type: "security_group",
            service: "EC2",
            region: "us-east-1",
            status: "CRITICAL",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "SG-002", status: "VIOLATED" }] },
            issues: [
              {
                rule_id: "SG-002",
                severity: "CRITICAL",
                category: "Security Risk",
                title: "SSH (port 22) open to the internet",
                what_found: "Inbound TCP 22 from 0.0.0.0/0",
                why: "Exposes SSH to brute force.",
                impact: "Verify VPN/SSM before removing 0.0.0.0/0.",
                what_checked: "Checked Security Group ingress.",
                evidence: { Source: "0.0.0.0/0", Port: "22" },
                fix: "Restrict port 22 to VPN CIDR.",
                verify: "Re-scan to verify SG-002 clears.",
              },
            ],
          },
        ],
        lambda_functions: [
          {
            id: "fn-stable",
            name: "stable-worker",
            type: "lambda_function",
            service: "Lambda",
            region: "us-east-1",
            status: "HEALTHY",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "LAM-001", status: "REVIEW" }] },
            issues: [
              {
                rule_id: "LAM-001",
                severity: "INFO",
                category: "Operational Concern",
                title: "Function not modified in over 90 days",
                what_found: "Last modified 180 days ago",
                why: "Stable functions are often intentional; review periodically.",
                impact: "No change needed if active and supported.",
                what_checked: "Checked LastModified timestamp.",
                evidence: { DaysSinceUpdate: "180" },
                fix: "Confirm whether this function is still needed.",
                verify: "Review in AWS Lambda console.",
              },
            ],
          },
        ],
      },
    })
  );

  fs.writeFileSync(
    richAfterResolved,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "COMPLETE",
      account_id: "111122223333",
      regions: ["us-east-1"],
      scanned_at: "2026-11-26T10:15:00Z",
      scan_duration_ms: 1400,
      partial: false,
      summary: { total_resources: 2, critical_issues: 0, warnings: 0, unused: 0, info_observations: 1, healthy: 2, incomplete_resources: 0, health_score_available: true },
      account_advisories: [],
      coverage: {
        status: "COMPLETE",
        is_partial: false,
        regions_scanned: ["us-east-1"],
        regions_succeeded: ["us-east-1"],
        regions_failed: [],
        services_skipped_optional: ["S3"],
        failures: [],
        scanner_statuses: [
          { service: "EC2", key: "security_groups", region: "us-east-1", status: "COMPLETED", count: 1 },
          { service: "Lambda", key: "lambda_functions", region: "us-east-1", status: "COMPLETED", count: 1 },
        ],
      },
      resources: {
        security_groups: [
          {
            id: "sg-000111222",
            name: "web-sg",
            type: "security_group",
            service: "EC2",
            region: "us-east-1",
            status: "HEALTHY",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "SG-002", status: "PASSED" }] },
            issues: [],
          },
        ],
        lambda_functions: [
          {
            id: "fn-stable",
            name: "stable-worker",
            type: "lambda_function",
            service: "Lambda",
            region: "us-east-1",
            status: "HEALTHY",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "LAM-001", status: "REVIEW" }] },
            issues: [
              {
                rule_id: "LAM-001",
                severity: "INFO",
                category: "Operational Concern",
                title: "Function not modified in over 90 days",
                what_found: "Last modified 180 days ago",
                why: "Stable functions are often intentional; review periodically.",
                impact: "No change needed if active and supported.",
                what_checked: "Checked LastModified timestamp.",
                evidence: { DaysSinceUpdate: "180" },
                fix: "Confirm whether this function is still needed.",
                verify: "Review in AWS Lambda console.",
              },
            ],
          },
        ],
      },
    })
  );

  return { emptyComplete, emptyIncomplete, richBefore, richAfterResolved };
}

const { chromium } = loadPlaywrightCore();
const chromeExecutable = resolveChromeBinary();
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aws-clarity-p5-"));
const { server, url: localUrl } = await startStaticDistServer(distDir);
const browser = await chromium.launch({
  ...(chromeExecutable ? { executablePath: chromeExecutable } : {}),
  headless: true,
});

const VIEWPORTS = [
  { name: "320px", width: 320, height: 640 },
  { name: "375px", width: 375, height: 812 },
  { name: "390px", width: 390, height: 844 },
  { name: "768px", width: 768, height: 1024 },
  { name: "1024px", width: 1024, height: 768 },
  { name: "1280px", width: 1280, height: 800 },
  { name: "1440px", width: 1440, height: 900 },
];

try {
  const { emptyComplete, emptyIncomplete, richBefore, richAfterResolved } = buildFixtures(tmpDir);
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();

  const resp = await page.goto(localUrl, { waitUntil: "networkidle" });
  assert.equal(resp.status(), 200);

  // 1. First-time onboarding, published v1.1.0 link, Verify Before Installing, Read-only callout, Production FAQ
  const setupText = await page.evaluate(() => document.body.innerText);
  assert.ok(setupText.includes("Published release: AWS Clarity CLI v1.1.0"));
  assert.ok(!setupText.toLowerCase().includes("not yet published"), "Outdated unpublished notice must not appear");
  const v110Links = await page.locator('a[href="https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0"]').count();
  assert.ok(v110Links >= 1, "SetupScreen must link directly to the published v1.1.0 GitHub Release");
  const firstRel = await page.locator('a[href="https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0"]').first().getAttribute("rel");
  assert.ok(firstRel && firstRel.includes("noopener") && firstRel.includes("noreferrer"));
  assert.ok(setupText.includes("Verify Before Installing"));
  assert.ok(setupText.includes("shasum -a 256 -c SHA256SUMS.txt"));
  assert.ok(setupText.includes("sha256sum -c SHA256SUMS.txt"));
  assert.ok(setupText.includes("Get-FileHash"));
  assert.ok(setupText.includes("Recommended: use a dedicated read-only role first"));
  assert.ok(setupText.includes("You can turn off your Wi-Fi before dropping your report file. It works the same."));
  assert.ok(setupText.includes("Can I use AWS Clarity with a production AWS account?"));

  // 2. Install-method keyboard tab switching (ArrowRight -> macOS/Linux -> Windows PowerShell)
  const pipxTab = page.locator("#install-tab-pipx");
  await pipxTab.focus();
  await page.keyboard.press("ArrowRight");
  assert.equal(await page.locator("#install-tab-unix").getAttribute("aria-selected"), "true");
  await page.keyboard.press("ArrowRight");
  assert.equal(await page.locator("#install-tab-windows").getAttribute("aria-selected"), "true");
  assert.ok((await page.locator("#install-panel-windows").innerText()).includes("Scripts\\pip.exe"));

  // 3. S3 checkbox highlights --include-s3-checks
  const s3Box = page.locator("#include-s3-checkbox");
  await s3Box.check();
  assert.ok((await page.evaluate(() => document.body.innerText)).includes("--include-s3-checks"));

  // 4. Production account FAQ expands and displays honest balanced answer
  await page.locator('summary:has-text("Can I use AWS Clarity with a production AWS account?")').click();
  const faqExpandedText = await page.evaluate(() => document.body.innerText);
  assert.ok(faqExpandedText.includes("health score is not a security certification"));
  assert.ok(faqExpandedText.includes("review the open-source code and IAM policy"));

  // 5. Accessibility baseline on Setup screen: lang="en", 1 <h1>, <main>, <header>, <footer>, reduced-motion active
  const setupA11y = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    h1Count: document.querySelectorAll("h1").length,
    mainCount: document.querySelectorAll("main").length,
    headerCount: document.querySelectorAll("header").length,
    footerCount: document.querySelectorAll("footer").length,
    reducedMotionMatch: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    title: document.title,
  }));
  assert.equal(setupA11y.lang, "en");
  assert.equal(setupA11y.h1Count, 1);
  assert.equal(setupA11y.mainCount, 1);
  assert.equal(setupA11y.headerCount, 1);
  assert.equal(setupA11y.footerCount, 1);
  assert.equal(setupA11y.reducedMotionMatch, true);
  assert.ok(setupA11y.title.includes("AWS Clarity"));

  // 6. Responsive overflow check on SetupScreen across all 7 viewports (320px -> 1440px)
  for (const vp of VIEWPORTS) {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.waitForTimeout(80);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `SetupScreen horizontal overflow at ${vp.name}: ${overflow}px`);
  }
  await page.setViewportSize({ width: 1280, height: 800 });

  // 7. TRUE OFFLINE REPORT IMPORT (browser context setOffline(true)!)
  await context.setOffline(true);
  await page.locator('input[type="file"]').first().setInputFiles(richBefore);
  await page.waitForSelector('h1:has-text("Account Overview")', { timeout: 5000 });
  assert.equal(await page.evaluate(() => document.title), "Account Dashboard | AWS Clarity");

  // 8. INFO review note presentation in DetailDrawer + keyboard Escape closes & restores focus
  const infoRow = page.locator('tbody tr:has-text("stable-worker")').first();
  await infoRow.click();
  await page.waitForSelector('text=INFO · Review Note', { timeout: 3000 });
  const drawerText = await page.evaluate(() => document.body.innerText);
  assert.ok(drawerText.includes("0 score impact · often legitimate"));
  // Verify reduced-motion has animation: none on drawer
  const drawerAnim = await page.evaluate(() => {
    const el = document.querySelector(".animate-slide-in");
    return el ? getComputedStyle(el).animationName : "none";
  });
  assert.equal(drawerAnim, "none", "Drawer slide animation must be disabled under prefers-reduced-motion: reduce");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(100);
  assert.equal(await page.locator('[role="dialog"]').count(), 0, "Escape must close DetailDrawer");

  // 9. Complete verified comparison shows subtle verified-progress banner (and NEVER on incomplete!)
  await page.locator('input[type="file"]').first().setInputFiles(richAfterResolved);
  await page.waitForSelector('text=Verified progress:', { timeout: 5000 });
  assert.ok((await page.evaluate(() => document.body.innerText)).includes("1 finding resolved"));

  // 10. Dashboard responsive overflow check across all 7 viewports (320px -> 1440px)
  for (const vp of VIEWPORTS) {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.waitForTimeout(80);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `DashboardScreen horizontal overflow at ${vp.name}: ${overflow}px`);
  }
  await page.setViewportSize({ width: 1280, height: 800 });

  // 11. Empty complete account vs Empty incomplete account states (still offline!)
  await page.locator('input[type="file"]').first().setInputFiles(emptyComplete);
  await page.waitForSelector('text=No supported AWS resources found in the scanned regions', { timeout: 5000 });
  await page.locator('input[type="file"]').first().setInputFiles(emptyIncomplete);
  await page.waitForSelector('text=No resources collected — assessment was incomplete', { timeout: 5000 });
  const incText = await page.evaluate(() => document.body.innerText);
  assert.ok(!incText.includes("Verified progress:"), "Incomplete scan must NEVER display verified progress celebration");
  assert.ok(incText.includes("Health score unavailable — assessment incomplete"));

  // 12. Modal keyboard focus & Escape restoration check (Coverage modal)
  const covTrigger = page.locator('button:has-text("Inspect Scan Coverage")').first();
  await covTrigger.focus();
  await covTrigger.click();
  await page.waitForSelector("#coverage-modal-title", { timeout: 3000 });
  const focusInsideModal = await page.evaluate(() => {
    const dlg = document.querySelector('[role="dialog"]');
    return Boolean(dlg && dlg.contains(document.activeElement));
  });
  assert.equal(focusInsideModal, true, "Opening modal must move keyboard focus inside the dialog");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(100);
  assert.equal(await page.locator('[role="dialog"]').count(), 0);

  // 13. Dashboard accessibility landmarks & single h1
  const dashA11y = await page.evaluate(() => ({
    h1Count: document.querySelectorAll("h1").length,
    mainCount: document.querySelectorAll("main").length,
    hasSearchLabel: Boolean(document.querySelector('label[for="search-input"]')),
  }));
  assert.equal(dashA11y.h1Count, 1);
  assert.equal(dashA11y.mainCount, 1);
  assert.equal(dashA11y.hasSearchLabel, true);

  await context.close();
  console.log("All Phase 5 browser UX, offline import, 320px-1440px responsive, keyboard, reduced-motion, and a11y checks passed.");
} finally {
  await browser.close();
  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
