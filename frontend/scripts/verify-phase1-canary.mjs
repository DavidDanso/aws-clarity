import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseLocalAssessmentReport } from "../src/utils/reportImporter.js";
import { buildInventoryCSV, sanitizeReportForSharing } from "../src/utils/reportSanitizer.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

// 1. Canary & malicious resource name verification across importer + sanitizer + CSV exporter
const xssName = '<script>alert("xss")</script>';
const formulaName = '=HYPERLINK("https://evil.example","click")';

const sampleReport = {
  schema_version: "aws-clarity-report/v1",
  scanner_version: "1.0.0",
  execution_mode: "local-cli",
  status: "COMPLETE",
  account_id: "123456789012",
  caller_arn: "arn:aws:sts::123456789012:assumed-role/ReadOnly/tester",
  regions: ["us-east-1"],
  coverage: { status: "COMPLETE", services_skipped_optional: ["S3"], failures: [] },
  resources: {
    lambda_functions: [
      {
        id: "fn-1",
        name: xssName,
        type: "lambda_function",
        service: "Lambda",
        status: "HEALTHY",
        region: "us-east-1",
        assessment: { status: "COMPLETE", checks: [] },
        issues: [],
        raw: { has_environment_variables: true, runtime: "python3.12" },
      },
    ],
    ec2_instances: [
      {
        id: "i-0123456789abcdef0",
        name: formulaName,
        type: "ec2_instance",
        service: "EC2",
        status: "HEALTHY",
        region: "us-east-1",
        assessment: { status: "COMPLETE", checks: [] },
        issues: [],
        raw: { state: "running", http_tokens: "required", public_ip: "203.0.113.55" },
      },
    ],
  },
};

const imported = parseLocalAssessmentReport(JSON.stringify(sampleReport));
assert.equal(imported.resources.lambda_functions[0].name, xssName, "XSS payload stays plain string data");

const sanitized = sanitizeReportForSharing(imported);
const sanitizedJson = JSON.stringify(sanitized);
assert.ok(!sanitizedJson.includes("123456789012"), "Account ID must be redacted in sanitized JSON");
assert.ok(!sanitizedJson.includes("203.0.113.55"), "Public IP must be redacted in sanitized JSON");
assert.ok(!sanitizedJson.includes(xssName), "Resource name must be replaced with alias in sanitized JSON");
assert.ok(!sanitizedJson.includes("CANARY_SECRET_LAMBDA_ENV"), "No canary secrets in sanitized JSON");

const fullCsv = buildInventoryCSV(Object.values(imported.resources).flat(), { sanitized: false });
assert.ok(fullCsv.includes(`"'=HYPERLINK`), "Formula injection must be neutralized in full CSV");
const sanitizedCsv = buildInventoryCSV(Object.values(sanitized.resources).flat(), { sanitized: true });
assert.ok(!sanitizedCsv.includes("203.0.113.55") && !sanitizedCsv.includes(xssName), "Sanitized CSV must redact names/IPs");

// 2. Verify Phase 1.7 Onboarding Step 2 callout is present OUTSIDE <details> and links IAM policy + CFN template
const setupSrc = fs.readFileSync(path.join(frontendRoot, "src", "pages", "SetupScreen.jsx"), "utf8");
const beforeDetails = setupSrc.split("<details")[0];
assert.ok(
  beforeDetails.includes("Recommended: use a dedicated read-only role first"),
  "Phase 1.7 read-only role recommendation must appear outside any collapsed <details> section"
);
assert.ok(
  beforeDetails.includes("docs/IAM_PERMISSIONS.md"),
  "Phase 1.7 callout must link directly to the IAM policy"
);
assert.ok(
  beforeDetails.includes("infra/aws-clarity-readonly-role.yaml"),
  "Phase 1.7 callout must link directly to the CloudFormation template"
);
assert.ok(
  beforeDetails.includes("--include-s3-checks"),
  "Phase 1.7 Step 2 must highlight --include-s3-checks when S3 checkbox is enabled"
);

console.log("All Phase 1 frontend canary, XSS/CSV safety, and Step 2 onboarding assertions passed.");
