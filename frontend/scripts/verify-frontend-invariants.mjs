import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildDemoScanData } from "../src/data/demoScanData.js";
import {
  DEFAULT_ZERO_COST_IAM_ACTIONS,
  IAM_POLICY_ACTIONS,
  OPTIONAL_S3_IAM_ACTIONS,
  SUPPORTED_SERVICES,
} from "../src/utils/constants.js";
import { computeScore } from "../src/utils/securityScore.js";
import { evaluateCheckStatus, SECURITY_CHECKS } from "../src/utils/securityChecksCatalog.js";
import { parseLocalAssessmentReport } from "../src/utils/reportImporter.js";
import { buildInventoryCSV, sanitizeReportForSharing } from "../src/utils/reportSanitizer.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

// 1. IAM policy invariants: 28 default zero-cost actions + 6 optional S3 actions = 34 total
assert.equal(DEFAULT_ZERO_COST_IAM_ACTIONS.length, 28, "Expected 28 zero-cost default IAM actions");
assert.equal(OPTIONAL_S3_IAM_ACTIONS.length, 6, "Expected 6 optional S3 IAM actions");
assert.equal(IAM_POLICY_ACTIONS.length, 34, "Expected 34 total IAM actions");
assert.ok(!IAM_POLICY_ACTIONS.includes("s3:ListBucket"), "s3:ListBucket must not be requested");
assert.ok(!IAM_POLICY_ACTIONS.includes("s3:GetObject"), "s3:GetObject must not be requested");
assert.ok(!IAM_POLICY_ACTIONS.includes("s3:GetBucketVersioning"), "Unused s3:GetBucketVersioning must not be requested");
assert.equal(SECURITY_CHECKS.length, 43, "Expected exactly 43 deterministic rules");

// 2. Demo fixture invariants & isolation
const demo = buildDemoScanData();
assert.equal(demo.is_demo, true);
assert.deepEqual(demo.coverage.services_supported, SUPPORTED_SERVICES);
const demoResources = Object.values(demo.resources).flat();
const demoStatuses = new Set(demoResources.map((r) => r.status));
for (const expected of ["CRITICAL", "WARNING", "UNUSED", "HEALTHY", "INCOMPLETE"]) {
  assert.ok(demoStatuses.has(expected), `Demo fixture missing status ${expected}`);
}
assert.ok(
  demoResources.some((r) => (r.issues || []).some((i) => i.severity === "INFO")),
  "Demo fixture should include INFO review observation"
);
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify(demo)),
  /Demo fixtures cannot be imported/i,
  "Demo fixture must be rejected by real report importer"
);

// 3. Report Importer security: malformed JSON, prototype pollution, credential leak blocking, control chars
assert.throws(() => parseLocalAssessmentReport("{bad json"), /Invalid JSON/i);
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify({ resources: { vpcs: [] }, SecretAccessKey: "wJalrXUtnFEMI/K7MDENG" })),
  /AWS credential fields/i,
  "Importer must block files containing AWS credentials"
);
const protoPayload = JSON.stringify({
  schema_version: "aws-clarity-report/v1",
  account_id: "123456789012",
  regions: ["us-east-1"],
  coverage: { status: "COMPLETE", services_skipped_optional: ["S3"], failures: [] },
  resources: {
    vpcs: [
      {
        id: "vpc-12345",
        name: "prod-vpc\u0000\u0007",
        type: "vpc",
        service: "VPC",
        status: "HEALTHY",
        region: "us-east-1",
        assessment: { status: "COMPLETE", checks: [{ rule_id: "VPC-001", status: "PASSED" }] },
        issues: [],
      },
    ],
  },
}).replace('"resources":{', '"__proto__":{"polluted":true},"resources":{');

const imported = parseLocalAssessmentReport(protoPayload);
assert.equal(({}).polluted, undefined, "Prototype must not be polluted");
assert.equal(imported.imported_locally, true);
assert.equal(imported.is_demo, false);
assert.equal(imported.resources.vpcs[0].name, "prod-vpc");

// 4. Optional S3 check status is SKIPPED_OPTIONAL (never PASSED or HEALTHY)
const s3Check = SECURITY_CHECKS.find((c) => c.id === "S3-002");
const skippedEval = evaluateCheckStatus(s3Check, [], ["S3"]);
assert.equal(skippedEval.status, "SKIPPED_OPTIONAL");

// 5. Health score withholding & INFO zero-deduction
const incompleteScore = computeScore(demoResources, true);
assert.equal(incompleteScore.isAvailable, false);
assert.equal(incompleteScore.score, null);
const infoOnlyScore = computeScore(
  [
    {
      id: "fn-1",
      status: "HEALTHY",
      assessment: { status: "COMPLETE", checks: [{ rule_id: "LAM-001", status: "REVIEW" }] },
      issues: [{ rule_id: "LAM-001", severity: "INFO", category: "Operational Concern" }],
    },
  ],
  false
);
assert.equal(infoOnlyScore.isAvailable, true);
assert.equal(infoOnlyScore.score, 100);

// 6. Sanitized export redacts Account IDs, ARNs, Resource Names, and IPs while keeping rule metadata
const sampleReal = {
  ...demo,
  is_demo: false,
  account_id: "987654321098",
  caller_arn: "arn:aws:sts::987654321098:assumed-role/Admin/jane",
};
const sanitized = sanitizeReportForSharing(sampleReal);
const serializedSanitized = JSON.stringify(sanitized);
assert.equal(sanitized.sanitized_for_sharing, true);
assert.equal(sanitized.account_id, "REDACTED-ACCOUNT");
assert.ok(!serializedSanitized.includes("987654321098"), "Account ID must be redacted");
assert.ok(!serializedSanitized.includes("prod-web-01"), "Resource names must be redacted");
assert.ok(!serializedSanitized.includes("203.0.113.24"), "Public IPs must be redacted");
assert.ok(serializedSanitized.includes("SG-002"), "Rule IDs must be preserved");
assert.ok(serializedSanitized.includes("0.0.0.0/0"), "Unrestricted CIDR 0.0.0.0/0 evidence should remain understandable");
const csv = buildInventoryCSV(Object.values(sanitized.resources).flat(), { sanitized: true });
assert.ok(csv.includes("SG-002") && !csv.includes("prod-web-01"));

// 6b. CSV formula-injection neutralization
const formulaCsv = buildInventoryCSV([
  {
    id: "=CMD|' /C calc'!A0",
    name: "+1+1",
    type: "s3_bucket",
    service: "S3",
    region: "us-east-1",
    status: "HEALTHY",
    assessment: { status: "COMPLETE", checks: [] },
    issues: [],
  },
  {
    id: "@SUM(1,1)",
    name: "-2+3",
    type: "ec2_instance",
    service: "EC2",
    region: "us-east-1",
    status: "HEALTHY",
    assessment: { status: "COMPLETE", checks: [] },
    issues: [],
  },
]);
assert.ok(formulaCsv.includes(`"'=CMD|' /C calc'!A0"`), "Leading '=' must be neutralized in CSV");
assert.ok(formulaCsv.includes(`"'+1+1"`), "Leading '+' must be neutralized in CSV");
assert.ok(formulaCsv.includes(`"'@SUM(1,1)"`), "Leading '@' must be neutralized in CSV");
assert.ok(formulaCsv.includes(`"'-2+3"`), "Leading '-' must be neutralized in CSV");

// 7. Production static build verification: strict CSP (`connect-src 'none'`) and zero network upload code
const distIndexPath = path.join(frontendRoot, "dist", "index.html");
if (fs.existsSync(distIndexPath)) {
  const indexHtml = fs.readFileSync(distIndexPath, "utf8");
  assert.ok(
    indexHtml.includes("Content-Security-Policy") && indexHtml.includes("connect-src 'none'"),
    "Production dist/index.html must enforce Content-Security-Policy with connect-src 'none'"
  );
  const assetsDir = path.join(frontendRoot, "dist", "assets");
  const jsFiles = fs.readdirSync(assetsDir).filter((f) => f.endsWith(".js"));
  for (const file of jsFiles) {
    const bundle = fs.readFileSync(path.join(assetsDir, file), "utf8");
    assert.ok(
      !bundle.includes("/__aws_clarity_api") && !bundle.includes("execute-api"),
      `Production bundle ${file} must not reference any hosted scan API endpoint`
    );
  }
}

console.log("All local-first privacy, report import, sanitization, CSP, and coverage invariants passed.");
