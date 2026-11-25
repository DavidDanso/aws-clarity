import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { computeScore } from "../src/utils/securityScore.js";
import { evaluateCheckStatus, SECURITY_CHECKS } from "../src/utils/securityChecksCatalog.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

// 1. Severity count distribution matches 13 CRITICAL / 20 WARNING / 3 UNUSED / 7 INFO = 43 rules
assert.equal(SECURITY_CHECKS.length, 43, "Expected exactly 43 deterministic rules");
const sevCounts = SECURITY_CHECKS.reduce((acc, c) => {
  acc[c.severity] = (acc[c.severity] || 0) + 1;
  return acc;
}, {});
assert.deepEqual(sevCounts, { CRITICAL: 13, WARNING: 20, UNUSED: 3, INFO: 7 });

// 2. Distinct check states: SKIPPED_OPTIONAL, NOT_APPLICABLE (No Resources), CHECK_FAILED, PASSED, REVIEW, VIOLATED
const rdsCheck = SECURITY_CHECKS.find((c) => c.id === "RDS-001");
const s3Check = SECURITY_CHECKS.find((c) => c.id === "S3-002");

// 2a. Zero resources + clean collection -> NOT_APPLICABLE ("No resources in account")
const zeroClean = evaluateCheckStatus(rdsCheck, [], [], [], [{ service: "RDS", status: "COMPLETED" }]);
assert.equal(zeroClean.status, "NOT_APPLICABLE");
assert.equal(zeroClean.label, "No resources in account");

// 2b. Zero resources + failed collection (AccessDenied) -> CHECK_FAILED (NEVER "No resources" or "PASSED")
const zeroFailed = evaluateCheckStatus(
  rdsCheck,
  [],
  [],
  [{ service: "RDS", reason: "AccessDenied" }],
  [{ service: "RDS", status: "FAILED" }]
);
assert.equal(zeroFailed.status, "CHECK_FAILED");

// 2c. Partial resource check failure (1 passed, 1 CHECK_FAILED) -> CHECK_FAILED (NEVER "PASSED")
const partialFailed = evaluateCheckStatus(
  rdsCheck,
  [
    { id: "db-1", name: "db-1", type: "rds_instance", status: "HEALTHY", assessment: { status: "COMPLETE", checks: [{ rule_id: "RDS-001", status: "PASSED" }] }, issues: [] },
    { id: "db-2", name: "db-2", type: "rds_instance", status: "INCOMPLETE", assessment: { status: "INCOMPLETE", checks: [{ rule_id: "RDS-001", status: "CHECK_FAILED" }] }, issues: [] },
  ],
  []
);
assert.equal(partialFailed.status, "CHECK_FAILED");
assert.ok(partialFailed.label.includes("1 verified, 1 failed"));

// 2d. Skipped optional S3 -> SKIPPED_OPTIONAL (never PASSED)
assert.equal(evaluateCheckStatus(s3Check, [], ["S3"]).status, "SKIPPED_OPTIONAL");

// 3. Health score integrity: CT-000 account advisory deducts -10 (empty unlogged account is NOT 100/100)
const scoreWithCt000 = computeScore(
  [],
  false,
  [{ rule_id: "CT-000", severity: "CRITICAL", category: "Security Risk" }]
);
assert.equal(scoreWithCt000.isAvailable, true);
assert.equal(scoreWithCt000.score, 90);
assert.equal(scoreWithCt000.critical, 1);

// 3b. Incomplete mandatory coverage ALWAYS withholds score even with 0 findings
const scoreIncomplete = computeScore([], true, []);
assert.equal(scoreIncomplete.isAvailable, false);
assert.equal(scoreIncomplete.score, null);
assert.equal(scoreIncomplete.label, "Unavailable");

// 4. Verify ALL href links in SetupScreen.jsx use absolute https:// URLs (zero relative links that 404 on static site)
const setupSrc = fs.readFileSync(path.join(frontendRoot, "src", "pages", "SetupScreen.jsx"), "utf8");
const hrefMatches = [...setupSrc.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
assert.ok(hrefMatches.length >= 4, "Expected external links in SetupScreen.jsx");
for (const href of hrefMatches) {
  assert.ok(href.startsWith("https://"), `SetupScreen.jsx link must be absolute https:// URL, got: ${href}`);
}

console.log("All Phase 2 frontend rule catalog, coverage/scoring integrity, and absolute-URL checks passed.");
