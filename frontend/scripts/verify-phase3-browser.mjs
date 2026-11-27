/**
 * verify-phase3-browser.mjs
 *
 * Reproducible headless Chrome/Chromium end-to-end browser security verifier
 * for the LOCAL PRODUCTION BUILD (`frontend/dist/`).
 *
 * Requirements (intentionally kept out of frontend/package.json so production
 * and standard CI installs stay minimal):
 *   1. Built frontend bundle: `npm --prefix frontend run build`
 *   2. Local Chrome or Chromium binary (auto-detected on macOS/Linux/Windows,
 *      or override via `CHROME_PATH=/path/to/chrome`).
 *   3. `playwright-core` installed in an isolated directory (e.g.,
 *      `npm --prefix /path/to/pw-runner install --no-save playwright-core`)
 *      and pointed to via `PLAYWRIGHT_CORE_DIR=/path/to/pw-runner`
 *      (or resolvable from standard NODE_PATH).
 *
 * Usage:
 *   npm --prefix frontend run build
 *   PLAYWRIGHT_CORE_DIR=/tmp/p3-browser node frontend/scripts/verify-phase3-browser.mjs
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
  console.error(
    "ERROR: `playwright-core` not found. Install it in an isolated folder without modifying frontend/package.json:\n" +
      "  mkdir -p /path/to/pw-runner && npm --prefix /path/to/pw-runner install --no-save playwright-core\n" +
      "Then run:\n" +
      "  PLAYWRIGHT_CORE_DIR=/path/to/pw-runner node frontend/scripts/verify-phase3-browser.mjs"
  );
  process.exit(2);
}

function resolveChromeBinary() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }
  const commonPaths = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ];
  for (const p of commonPaths) {
    if (fs.existsSync(p)) return p;
  }
  return undefined; // Fall back to Playwright-managed Chromium if installed
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
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

function buildSyntheticFixtures(tmpDir) {
  const badCreds = path.join(tmpDir, "bad-creds.json");
  const scan1 = path.join(tmpDir, "scan1-xss-canary.json");
  const scan2 = path.join(tmpDir, "scan2-incomplete.json");

  fs.writeFileSync(
    badCreds,
    JSON.stringify({ resources: { vpcs: [] }, secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" })
  );

  fs.writeFileSync(
    scan1,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "COMPLETE",
      account_id: "987654321098",
      caller_arn: "arn:aws:sts::987654321098:assumed-role/ClarityReadOnly/tester",
      regions: ["us-east-1"],
      scanned_at: "2026-11-25T20:00:00Z",
      scan_duration_ms: 1200,
      partial: false,
      summary: { total_resources: 2, critical_issues: 1, warnings: 1, unused: 0, info_observations: 0, healthy: 0, incomplete_resources: 0, health_score_available: true },
      account_advisories: [],
      coverage: {
        status: "COMPLETE",
        is_partial: false,
        regions_scanned: ["us-east-1"],
        regions_succeeded: ["us-east-1"],
        regions_failed: [],
        services_supported: ["EC2", "VPC", "S3", "IAM", "Lambda", "RDS", "DynamoDB", "EBS", "CloudWatch", "CloudTrail"],
        services_skipped_optional: ["S3"],
        failures: [],
        scanner_statuses: [
          { service: "EC2", key: "security_groups", region: "us-east-1", status: "COMPLETED", count: 1 },
          { service: "IAM", key: "iam_users", region: "global", status: "COMPLETED", count: 1 },
        ],
      },
      resources: {
        security_groups: [
          {
            id: "sg-0123456789abcdef0",
            name: '<img src=x onerror="window.__xss=1"><script>window.__xss2=1</script>=HYPERLINK("https://evil.example")',
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
                title: "SSH (port 22) open to the internet on 198.51.100.42",
                what_found: "Inbound SSH from 0.0.0.0/0",
                why: "Exposes SSH to brute force.",
                impact: "Consequences & dependencies: Restricting port 22 immediately blocks unlisted admin IPs; verify VPN/SSM first.",
                what_checked: "Inspected Security Group ingress.",
                evidence: { SecurityGroup: "sg-0123456789abcdef0", Source: "0.0.0.0/0", PublicIp: "198.51.100.42" },
                fix: "Restrict TCP port 22 to your VPN CIDR.",
                verify: "Re-scan to confirm SG-002 clears.",
              },
            ],
            raw: { vpc_id: "vpc-0a1b2c3d4e5f67890" },
          },
        ],
        iam_users: [
          {
            id: "AIDA1234567890EXAMPLE",
            name: "CANARY_TAG_TOKEN",
            type: "iam_user",
            service: "IAM",
            region: "global",
            status: "WARNING",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "IAM-010", status: "VIOLATED" }] },
            issues: [
              {
                rule_id: "IAM-010",
                severity: "WARNING",
                category: "Security Risk",
                title: "Long-lived active IAM access key (>90 days)",
                what_found: "Key AKIAIOSFODNN7EXAMPLE is 140 days old",
                why: "Static keys carry higher blast radius if leaked.",
                impact: "Consequences & dependencies: Deactivate old key before deleting.",
                what_checked: "Inspected ListAccessKeys.",
                evidence: { User: "CANARY_TAG_TOKEN", KeysOver90Days: "AKIAIOSFODNN7EXAMPLE (140d)" },
                fix: "Rotate AKIAIOSFODNN7EXAMPLE safely.",
                verify: "Re-scan after rotating key.",
              },
            ],
            raw: { arn: "arn:aws:iam::987654321098:user/CANARY_TAG_TOKEN" },
          },
        ],
      },
    })
  );

  fs.writeFileSync(
    scan2,
    JSON.stringify({
      schema_version: "aws-clarity-report/v1",
      scanner_version: "1.1.0",
      execution_mode: "local-cli",
      status: "INCOMPLETE",
      account_id: "987654321098",
      caller_arn: "arn:aws:sts::987654321098:assumed-role/ClarityReadOnly/tester",
      regions: ["us-east-1"],
      scanned_at: "2026-11-25T20:05:00Z",
      scan_duration_ms: 900,
      partial: true,
      summary: { total_resources: 1, critical_issues: 0, warnings: 1, unused: 0, info_observations: 0, healthy: 0, incomplete_resources: 0, health_score_available: false },
      account_advisories: [],
      coverage: {
        status: "INCOMPLETE",
        is_partial: true,
        regions_scanned: ["us-east-1"],
        regions_succeeded: [],
        regions_failed: ["us-east-1"],
        services_supported: ["EC2", "VPC", "S3", "IAM", "Lambda", "RDS", "DynamoDB", "EBS", "CloudWatch", "CloudTrail"],
        services_skipped_optional: ["S3"],
        failures: [{ service: "EC2", label: "Security Groups", region: "us-east-1", reason: "AccessDenied", required_permission: "ec2:DescribeSecurityGroups" }],
        scanner_statuses: [
          { service: "EC2", key: "security_groups", region: "us-east-1", status: "FAILED", count: 0, reason: "AccessDenied" },
          { service: "IAM", key: "iam_users", region: "global", status: "COMPLETED", count: 1 },
        ],
      },
      resources: {
        security_groups: [],
        iam_users: [
          {
            id: "AIDA1234567890EXAMPLE",
            name: "CANARY_TAG_TOKEN",
            type: "iam_user",
            service: "IAM",
            region: "global",
            status: "WARNING",
            assessment: { status: "COMPLETE", checks: [{ rule_id: "IAM-010", status: "VIOLATED" }] },
            issues: [
              {
                rule_id: "IAM-010",
                severity: "WARNING",
                category: "Security Risk",
                title: "Long-lived active IAM access key (>90 days)",
                what_found: "Key AKIAIOSFODNN7EXAMPLE is 140 days old",
                why: "Static keys carry higher blast radius if leaked.",
                impact: "Consequences & dependencies: Deactivate old key before deleting.",
                what_checked: "Inspected ListAccessKeys.",
                evidence: { User: "CANARY_TAG_TOKEN", KeysOver90Days: "AKIAIOSFODNN7EXAMPLE (140d)" },
                fix: "Rotate AKIAIOSFODNN7EXAMPLE safely.",
                verify: "Re-scan after rotating key.",
              },
            ],
            raw: { arn: "arn:aws:iam::987654321098:user/CANARY_TAG_TOKEN" },
          },
        ],
      },
    })
  );

  return { badCreds, scan1, scan2 };
}

const { chromium } = loadPlaywrightCore();
const chromeExecutable = resolveChromeBinary();
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aws-clarity-p3-"));
const { server, url: localUrl } = await startStaticDistServer(distDir);
const browser = await chromium.launch({
  ...(chromeExecutable ? { executablePath: chromeExecutable } : {}),
  headless: true,
});

try {
  const { badCreds, scan1, scan2 } = buildSyntheticFixtures(tmpDir);
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, acceptDownloads: true });
  const page = await context.newPage();

  const postLoadRequests = [];
  let trackingPostLoad = false;
  page.on("request", (req) => {
    if (trackingPostLoad) postLoadRequests.push({ url: req.url(), method: req.method(), type: req.resourceType() });
  });

  const resp = await page.goto(localUrl, { waitUntil: "networkidle" });
  assert.equal(resp.status(), 200);

  // 1. Live <meta> CSP enforcement
  const cspRes = await page.evaluate(async () => {
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content") || "";
    let blocked = false;
    try {
      await fetch("https://example.com/exfil");
    } catch {
      blocked = true;
    }
    return { meta, blocked };
  });
  assert.ok(cspRes.meta.includes("connect-src 'none'"));
  assert.equal(cspRes.blocked, true, "CSP connect-src 'none' must actively block outbound fetch");

  // 2. Guided Step 2 read-only role callout + absolute https:// links across landing page
  await page.locator("#step-2-trigger").click();
  await page.waitForSelector('#step-2-panel:not([hidden])', { timeout: 3000 });
  const step2 = await page.evaluate(() => ({
    hasCallout: document.body.innerText.includes("Recommended: use a dedicated read-only role first"),
    allHttps: Array.from(document.querySelectorAll("a")).every((a) => (a.getAttribute("href") || "").startsWith("https://")),
  }));
  assert.equal(step2.hasCallout, true);
  assert.equal(step2.allHttps, true);

  // Jump to Step 3 for report import tests
  await page.locator("#step-3-trigger").click();
  await page.waitForSelector('#step-3-panel:not([hidden])', { timeout: 3000 });

  trackingPostLoad = true;

  // 3. Credential file rejected cleanly
  await page.locator('input[type="file"]').first().setInputFiles(badCreds);
  await page.waitForTimeout(250);
  const errBody = await page.evaluate(() => document.body.innerText);
  assert.ok(errBody.includes("AWS credential fields"));
  assert.ok(!errBody.includes("wJalrXUtnFEMI"));

  // 4. Import XSS + canary report
  await page.locator('input[type="file"]').first().setInputFiles(scan1);
  await page.waitForSelector('h2:has-text("All Resources")', { timeout: 5000 });
  const domState = await page.evaluate(() => ({
    xss1: window.__xss,
    xss2: window.__xss2,
    injectedImgs: document.querySelectorAll('img[src="x"]').length,
    literalXss: document.body.innerText.includes("<img src=x onerror="),
    localStorageLen: localStorage.length,
    sessionStorageLen: sessionStorage.length,
    cookies: document.cookie,
  }));
  assert.equal(domState.xss1, undefined);
  assert.equal(domState.xss2, undefined);
  assert.equal(domState.injectedImgs, 0);
  assert.equal(domState.literalXss, true);
  assert.equal(domState.localStorageLen, 0);
  assert.equal(domState.sessionStorageLen, 0);
  assert.equal(domState.cookies, "");

  // 5. Search & Detail Drawer impact
  const searchBox = page.locator('input[placeholder*="Search"]').first();
  await searchBox.fill("CANARY_TAG_TOKEN");
  await page.waitForTimeout(150);
  assert.equal(await page.locator("tbody tr").count(), 1);
  await searchBox.fill("");
  await page.waitForTimeout(150);
  assert.equal(await page.locator("tbody tr").count(), 2);

  await page.locator("tbody tr").first().click();
  await page.waitForSelector('text=Before You Change (Impact & Dependencies)', { timeout: 3000 });
  await page.locator('button[aria-label="Close inspection drawer"]').click();

  // 6. Scan Diff with incomplete scan -> Unverified (never Resolved) + score withheld
  await page.locator('input[type="file"]').first().setInputFiles(scan2);
  await page.waitForSelector('text=Health score unavailable', { timeout: 5000 });
  const diffText = await page.evaluate(() => document.body.innerText);
  assert.ok(diffText.includes("Unverified"));
  assert.ok(diffText.includes("incomplete coverage"));

  // 7. Export modal disclaimer + all 4 exports
  for (const label of ["Download Sanitized JSON", "Download Sanitized CSV", "Download Full JSON", "Download Full CSV"]) {
    if (!(await page.locator("#export-modal-title").isVisible())) {
      await page.locator('button:has-text("Export")').first().click();
      await page.waitForSelector("#export-modal-title", { timeout: 3000 });
      const modalText = await page.evaluate(() => document.body.innerText);
      assert.ok(
        modalText.includes(
          "Sanitized reports use best-effort redaction. They are not guaranteed to be completely anonymous. Inspect the file before sharing."
        )
      );
    }
    const [dl] = await Promise.all([page.waitForEvent("download"), page.locator(`button:has-text("${label}")`).click()]);
    const content = fs.readFileSync(await dl.path(), "utf8");
    if (label.includes("Sanitized")) {
      assert.ok(!content.includes("987654321098"));
      assert.ok(!content.includes("CANARY_TAG_TOKEN"));
      assert.ok(!content.includes("AKIAIOSFODNN7EXAMPLE"));
    }
  }

  // 8. Clear controls + zero post-load external network requests
  await page.locator('button:has-text("Trust & Privacy")').first().click();
  await page.waitForSelector("#trust-modal-title", { timeout: 3000 });
  await page.locator('button:has-text("Clear Diff History")').click();
  await page.locator('button:has-text("Clear All Local Browser Data")').click();
  await page.waitForSelector('h1:has-text("Understand your AWS configuration")', { timeout: 5000 });

  const externalReqs = postLoadRequests.filter((r) => !r.url.startsWith("blob:") && !r.url.startsWith("data:"));
  assert.equal(externalReqs.length, 0, `Unexpected network activity: ${JSON.stringify(externalReqs)}`);

  // 9. Reload clears in-memory report + Mobile 390x844 overflow check
  trackingPostLoad = false;
  await page.locator('input[type="file"]').first().setInputFiles(scan1);
  await page.waitForSelector('h2:has-text("All Resources")', { timeout: 5000 });
  await page.reload({ waitUntil: "networkidle" });
  const reloadedText = await page.evaluate(() => document.body.innerText);
  assert.ok(reloadedText.includes("Understand your AWS configuration") && !reloadedText.includes("CANARY_TAG_TOKEN"));

  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(150);
  assert.ok((await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)) <= 0);
  await page.locator('input[type="file"]').first().setInputFiles(scan1);
  await page.waitForSelector('h2:has-text("All Resources")', { timeout: 5000 });
  await page.waitForTimeout(150);
  assert.ok((await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)) <= 0);

  await context.close();
  console.log("All Phase 3 local production-build headless browser security assertions passed.");
} finally {
  await browser.close();
  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
