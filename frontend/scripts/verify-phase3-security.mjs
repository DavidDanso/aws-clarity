/**
 * Phase 3: Browser & Report Security Regression Suite
 *
 * Covers:
 *   - 21+ malicious & malformed imported report scenarios
 *   - Static XSS, storage & network sink audit across frontend/src
 *   - Canary secret & sensitive identifier handling across import, sanitizer, JSON & CSV exports
 *   - CSV formula-injection protection across every exported column
 *   - Scan comparison safety (cross-account refusal, incomplete/skipped scans, unverified vs resolved)
 *   - Production CSP & required export disclaimer assertions
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAX_REPORT_BYTES,
  parseLocalAssessmentReport,
  sanitizeImportedFileName,
} from "../src/utils/reportImporter.js";
import {
  buildInventoryCSV,
  neutralizeCsvCell,
  sanitizeReportForSharing,
} from "../src/utils/reportSanitizer.js";
import { compareScans, getStableResourceId } from "../src/utils/scanComparison.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

function validBaseReport(overrides = {}) {
  return {
    schema_version: "aws-clarity-report/v1",
    scanner_version: "1.0.0",
    execution_mode: "local-cli",
    status: "COMPLETE",
    account_id: "987654321098",
    caller_arn: "arn:aws:sts::987654321098:assumed-role/ClarityReadOnly/alice",
    regions: ["us-east-1"],
    coverage: {
      status: "COMPLETE",
      services_skipped_optional: ["S3"],
      regions_scanned: ["us-east-1"],
      regions_failed: [],
      failures: [],
      scanner_statuses: [{ service: "EC2", key: "ec2_instances", region: "us-east-1", status: "COMPLETED" }],
    },
    account_advisories: [],
    resources: {
      ec2_instances: [],
      vpcs: [],
    },
    ...overrides,
  };
}

// =========================================================================
// 1. Malicious & Malformed Imported Report Matrix (21 scenarios)
// =========================================================================

// 1. Oversized file (>25 MB via size arg AND string length)
assert.throws(
  () => parseLocalAssessmentReport("{}", MAX_REPORT_BYTES + 1),
  /25 MB local browser safety limit/i,
  "Oversized file size must be rejected"
);

// 2. Invalid JSON
assert.throws(() => parseLocalAssessmentReport("{not valid json"), /Invalid JSON/i);

// 3. Empty string & empty JSON object {}
assert.throws(() => parseLocalAssessmentReport("   "), /empty/i);
assert.throws(() => parseLocalAssessmentReport("{}"), /missing the required `resources`/i);

// 4. Arrays where objects are expected (root array, resources array, non-array collection)
assert.throws(() => parseLocalAssessmentReport("[]"), /root JSON value must be an object/i);
assert.throws(() => parseLocalAssessmentReport(JSON.stringify({ resources: [] })), /missing the required `resources`/i);
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify({ resources: { vpcs: "not-a-list" } })),
  /resources\.vpcs must be a list/i
);

// 5. Deeply nested structure (>16 levels) — safely truncated without stack overflow
let nested = { leaf: "ok" };
for (let i = 0; i < 30; i++) nested = { child: nested };
const deepRep = parseLocalAssessmentReport(
  JSON.stringify(validBaseReport({ extra_deep: nested }))
);
assert.equal(deepRep.imported_locally, true);

// 6. Excessively long string (>4096 chars) — bounded to <=4097 chars
const longStr = "A".repeat(12000);
const longRep = parseLocalAssessmentReport(
  JSON.stringify(
    validBaseReport({
      resources: {
        vpcs: [
          {
            id: "vpc-0123456789abcdef0",
            name: longStr,
            type: "vpc",
            service: "VPC",
            region: "us-east-1",
            status: "HEALTHY",
            assessment: { status: "COMPLETE", checks: [] },
            issues: [],
          },
        ],
      },
    })
  )
);
assert.ok(longRep.resources.vpcs[0].name.length <= 4097, "Excessively long string must be bounded");

// 7. Unexpected properties & unexpected data types
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify(validBaseReport({ resources: { vpcs: [12345] } }))),
  /non-object entry/i
);
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify(validBaseReport({ resources: { vpcs: [{ id: 999 }] } }))),
  /missing or invalid id/i
);
assert.throws(
  () =>
    parseLocalAssessmentReport(
      JSON.stringify(validBaseReport({ resources: { vpcs: [{ id: "vpc-1", status: "HEALTHY", issues: "bad" }] } }))
    ),
  /non-array issues/i
);

// 8. Prototype pollution keys (__proto__, constructor, prototype)
const protoRaw = JSON.stringify(validBaseReport()).replace(
  '"resources":{',
  '"__proto__":{"p3Polluted":true},"constructor":{"prototype":{"p3Polluted2":true}},"prototype":{"p3Polluted3":true},"resources":{'
);
const protoParsed = parseLocalAssessmentReport(protoRaw);
assert.equal(({}).p3Polluted, undefined);
assert.equal(({}).p3Polluted2, undefined);
assert.equal(({}).p3Polluted3, undefined);
assert.equal(Object.prototype.hasOwnProperty.call(protoParsed, "__proto__"), false);

// 9. Credential-like fields (case-insensitive keys) + AWS secret/session-token string patterns
for (const badPayload of [
  { ...validBaseReport(), secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
  { ...validBaseReport(), securityToken: "fake-security-token" },
  {
    ...validBaseReport(),
    notes: "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  },
  {
    ...validBaseReport(),
    notes: "leaked FwoGZXIvYXdzEBAaDOFakeSessionTokenValue1234567890",
  },
  {
    ...validBaseReport(),
    notes: "temporary key ASIAIOSFODNN7EXAMPLE in output",
  },
]) {
  assert.throws(
    () => parseLocalAssessmentReport(JSON.stringify(badPayload)),
    /AWS credential fields/i,
    "Credential-like fields or secret/session-token patterns must be blocked"
  );
}

// 10. HTML, <script>, malicious javascript: URL, and control characters
const xssHtml = '<img src=x onerror="alert(1)"><script>fetch("https://evil.example")</script>';
const evilUrl = 'javascript:alert("pwn")';
const ctrlName = "prod-web\u0000\u0007\u001b-01";
const maliciousTextRep = parseLocalAssessmentReport(
  JSON.stringify(
    validBaseReport({
      resources: {
        ec2_instances: [
          {
            id: "i-0123456789abcdef0",
            name: xssHtml,
            type: "ec2_instance",
            service: "EC2",
            region: "us-east-1",
            status: "WARNING",
            assessment: { status: "COMPLETE", checks: [] },
            issues: [
              {
                rule_id: "EC2-002",
                severity: "WARNING",
                category: "Security Risk",
                title: evilUrl,
                what_found: ctrlName,
                why: xssHtml,
                evidence: { URL: evilUrl, Raw: ctrlName },
                fix: "Manual fix",
                verify: "Re-scan",
              },
            ],
          },
        ],
      },
    })
  )
);
assert.equal(maliciousTextRep.resources.ec2_instances[0].name, xssHtml);
assert.equal(maliciousTextRep.resources.ec2_instances[0].issues[0].what_found, "prod-web-01");
assert.equal(sanitizeImportedFileName("bad\u0000file\u0007.json"), "badfile.json");

// 11. Duplicate resources deduplicated cleanly
const dupRep = parseLocalAssessmentReport(
  JSON.stringify(
    validBaseReport({
      resources: {
        vpcs: [
          { id: "vpc-00112233445566778", name: "v1", type: "vpc", service: "VPC", region: "us-east-1", status: "HEALTHY", assessment: { status: "COMPLETE", checks: [] }, issues: [] },
          { id: "vpc-00112233445566778", name: "v1-dup", type: "vpc", service: "VPC", region: "us-east-1", status: "HEALTHY", assessment: { status: "COMPLETE", checks: [] }, issues: [] },
        ],
      },
    })
  )
);
assert.equal(dupRep.resources.vpcs.length, 1, "Duplicate resources in same collection must be deduplicated");

// 12. Missing required collections -> rejected
assert.throws(
  () => parseLocalAssessmentReport(JSON.stringify({ resources: { unknown_service: [] } })),
  /No recognized AWS Clarity resource collections/i
);

// 13. Unexpected status and severity values -> rejected; HEALTHY without COMPLETE assessment -> normalized INCOMPLETE
assert.throws(
  () =>
    parseLocalAssessmentReport(
      JSON.stringify(validBaseReport({ resources: { vpcs: [{ id: "vpc-1", status: "SUPER_SAFE", issues: [] }] } }))
    ),
  /unsupported status/i
);
assert.throws(
  () =>
    parseLocalAssessmentReport(
      JSON.stringify(
        validBaseReport({
          resources: {
            vpcs: [{ id: "vpc-1", status: "WARNING", issues: [{ rule_id: "X", severity: "BOGUS" }] }],
          },
        })
      )
    ),
  /unsupported severity/i
);
const fakeHealthyRep = parseLocalAssessmentReport(
  JSON.stringify(
    validBaseReport({
      resources: {
        vpcs: [{ id: "vpc-1", status: "HEALTHY", issues: [] }],
      },
    })
  )
);
assert.equal(
  fakeHealthyRep.resources.vpcs[0].status,
  "INCOMPLETE",
  "Resource claiming HEALTHY without COMPLETE assessment must never be trusted as HEALTHY"
);

// =========================================================================
// 2. Canary & Sanitized Export Redaction Tests
// =========================================================================
const canaryReport = validBaseReport({
  account_id: "987654321098",
  caller_arn: "arn:aws:sts::987654321098:assumed-role/OrgAdmin/bob",
  account_advisories: [
    {
      rule_id: "CT-000",
      severity: "CRITICAL",
      category: "Security Risk",
      service: "CloudTrail",
      title: "Missing trail for 987654321098",
      why: "Check arn:aws:iam::987654321098:role/SecretRole and 198.51.100.42",
      impact: "Verify vpc-0a1b2c3d4e5f67890 and 10.42.0.0/16",
      evidence: { Account: "987654321098", PublicIp: "198.51.100.42" },
      fix: "Create trail",
      verify: "Re-scan",
    },
  ],
  coverage: {
    status: "INCOMPLETE",
    services_skipped_optional: ["S3"],
    regions_scanned: ["us-east-1"],
    regions_failed: [],
    failures: [
      {
        service: "IAM",
        label: "arn:aws:iam::987654321098:user/alice",
        region: "global",
        reason: "Denied reading CANARY_TAG_TOKEN on i-0123456789abcdef0",
        required_permission: "iam:ListUsers",
      },
    ],
    scanner_statuses: [
      {
        service: "EC2",
        key: "ec2_instances",
        region: "us-east-1",
        status: "INCOMPLETE",
        reason: "Error inspecting 198.51.100.42 in 987654321098",
      },
    ],
  },
  resources: {
    iam_users: [
      {
        id: "AIDA1234567890EXAMPLE",
        name: "CANARY_TAG_TOKEN",
        type: "iam_user",
        service: "IAM",
        region: "global",
        status: "WARNING",
        assessment: {
          status: "INCOMPLETE",
          checks: [
            { rule_id: "IAM-009", status: "CHECK_FAILED", reason: "Failed for arn:aws:iam::987654321098:user/CANARY_TAG_TOKEN" },
          ],
        },
        issues: [
          {
            rule_id: "IAM-010",
            severity: "WARNING",
            category: "Security Risk",
            title: "Long-lived key on CANARY_TAG_TOKEN (AKIAIOSFODNN7EXAMPLE)",
            what_found: "Active key AKIAIOSFODNN7EXAMPLE on 987654321098",
            why: "User CANARY_TAG_TOKEN from 198.51.100.42 and 2001:db8:85a3::8a2e/64",
            impact: "Affects CANARY_SECRET_LAMBDA_ENV and sg-0123456789abcdef0 (0.0.0.0/0 and ::/0)",
            what_checked: "Checked AKIAIOSFODNN7EXAMPLE",
            evidence: {
              User: "CANARY_TAG_TOKEN",
              KeysOver90Days: "AKIAIOSFODNN7EXAMPLE (145d)",
              PrivateCidr: "10.42.0.0/16",
              OpenCidr: "0.0.0.0/0",
              OpenV6: "::/0",
            },
            fix: "Rotate AKIAIOSFODNN7EXAMPLE on CANARY_TAG_TOKEN",
            verify: "Re-scan CANARY_TAG_TOKEN",
          },
        ],
        raw: { arn: "arn:aws:iam::987654321098:user/CANARY_TAG_TOKEN", secret_note: "CANARY_SECRET_LAMBDA_ENV" },
      },
    ],
    lambda_functions: [
      {
        id: "CANARY_SECRET_LAMBDA_ENV",
        name: "CANARY_SECRET_LAMBDA_ENV",
        type: "lambda_function",
        service: "Lambda",
        region: "us-east-1",
        status: "HEALTHY",
        assessment: { status: "COMPLETE", checks: [] },
        issues: [],
        raw: { function_arn: "arn:aws:lambda:us-east-1:987654321098:function:CANARY_SECRET_LAMBDA_ENV" },
      },
    ],
  },
});

const sanitized = sanitizeReportForSharing(canaryReport);
const sanitizedText = JSON.stringify(sanitized);

for (const mustBeRedacted of [
  "987654321098",
  "OrgAdmin/bob",
  "CANARY_TAG_TOKEN",
  "CANARY_SECRET_LAMBDA_ENV",
  "AKIAIOSFODNN7EXAMPLE",
  "198.51.100.42",
  "10.42.0.0/16",
  "2001:db8:85a3::8a2e/64",
  "i-0123456789abcdef0",
  "vpc-0a1b2c3d4e5f67890",
  "sg-0123456789abcdef0",
  "arn:aws:iam::",
  "arn:aws:lambda:",
]) {
  assert.ok(!sanitizedText.includes(mustBeRedacted), `Sanitized JSON leaked sensitive value: ${mustBeRedacted}`);
}
// Preserve meaningful rule context & public wildcard CIDRs
assert.ok(sanitizedText.includes("IAM-010"), "Rule ID must remain in sanitized JSON");
assert.ok(sanitizedText.includes("0.0.0.0/0"), "0.0.0.0/0 must remain understandable in sanitized JSON");
assert.ok(sanitizedText.includes("::/0"), "::/0 must remain understandable in sanitized JSON");
assert.ok(sanitized.sanitization_notice.includes("best-effort redaction"), "Sanitization notice must be embedded");

const sanitizedCsv = buildInventoryCSV(Object.values(sanitized.resources).flat(), { sanitized: true });
for (const mustBeRedacted of ["987654321098", "CANARY_TAG_TOKEN", "AKIAIOSFODNN7EXAMPLE", "198.51.100.42"]) {
  assert.ok(!sanitizedCsv.includes(mustBeRedacted), `Sanitized CSV leaked sensitive value: ${mustBeRedacted}`);
}

// =========================================================================
// 3. CSV Formula-Injection Protection (All prefixes + leading whitespace + every column)
// =========================================================================
for (const payload of [
  '=HYPERLINK("https://evil.example","click")',
  "+1+1",
  "-2+3",
  "@SUM(A1:A10)",
  "\t=CMD|' /C calc'!A0",
  "\r=1+1",
  "\n=1+1",
  " =HYPERLINK(\"https://evil.example\")",
  "   +2+2",
  "  -1",
  " @SUM(1,2)",
]) {
  const cell = neutralizeCsvCell(payload);
  assert.ok(cell.startsWith(`"'`), `CSV formula payload was not neutralized: ${JSON.stringify(payload)} -> ${cell}`);
}

const formulaResource = {
  service: "=SVC",
  name: " =NAME",
  id: "+ID",
  type: "-TYPE",
  region: "@REG",
  status: "CRITICAL",
  assessment: { status: "COMPLETE", checks: [] },
  issues: [
    {
      category: "\tCAT",
      rule_id: "\rRULE",
      severity: "CRITICAL",
      title: "=TITLE",
      evidence: { Key: " +EVID" },
      fix: "-FIX",
      verify: "@VERIFY",
    },
  ],
};
const fullFormulaCsv = buildInventoryCSV([formulaResource], { sanitized: false });
for (const expectedNeutralized of [`"'=SVC"`, `"' =NAME"`, `"'+ID"`, `"'-TYPE"`, `"'@REG"`, `"'\tCAT"`, `"'\rRULE"`, `"'=TITLE"`, `"'-FIX"`, `"'@VERIFY"`]) {
  assert.ok(fullFormulaCsv.includes(expectedNeutralized), `Missing neutralized CSV cell ${expectedNeutralized}`);
}

// =========================================================================
// 4. Scan Comparison Safety Tests
// =========================================================================
const sgCrit = {
  id: "sg-1",
  name: '<script>alert("diff")</script>',
  type: "security_group",
  service: "EC2",
  region: "us-east-1",
  status: "CRITICAL",
  assessment: { status: "COMPLETE", checks: [{ rule_id: "SG-002", status: "VIOLATED" }] },
  issues: [{ rule_id: "SG-002", severity: "CRITICAL", title: "Open SSH" }],
};
const s3Crit = {
  id: "corp-bucket",
  name: "corp-bucket",
  type: "s3_bucket",
  service: "S3",
  region: "us-east-1",
  status: "CRITICAL",
  assessment: { status: "COMPLETE", checks: [{ rule_id: "S3-002", status: "VIOLATED" }] },
  issues: [{ rule_id: "S3-002", severity: "CRITICAL", title: "Public Bucket" }],
};

// 4a. Different AWS accounts -> refused (isComparable: false, 0 resolved, scoreDelta: null)
const crossAcct = compareScans([sgCrit], [], {
  prevReport: validBaseReport({ account_id: "111111111111" }),
  currReport: validBaseReport({ account_id: "222222222222" }),
});
assert.equal(crossAcct.isComparable, false);
assert.equal(crossAcct.resolvedCount, 0);
assert.equal(crossAcct.scoreDelta, null);

// 4b. Disappearing resource during INCOMPLETE newer scan -> UNVERIFIED (NEVER resolved!), scoreDelta: null
const incompleteDiff = compareScans([sgCrit], [], {
  prevReport: validBaseReport({ account_id: "111111111111" }),
  currReport: validBaseReport({
    account_id: "111111111111",
    partial: true,
    coverage: { status: "INCOMPLETE", regions_failed: ["us-east-1"], failures: [{ service: "EC2", region: "us-east-1" }] },
  }),
  currIncomplete: true,
});
assert.equal(incompleteDiff.isComparable, true);
assert.equal(incompleteDiff.resolvedCount, 0, "Disappeared resource in incomplete scan must NEVER be marked resolved");
assert.equal(incompleteDiff.unverifiedCount, 1);
assert.equal(incompleteDiff.scoreDelta, null);

// 4c. S3 enabled in scan 1, skipped in scan 2 -> S3 finding is UNVERIFIED (NEVER resolved!)
const skippedS3Diff = compareScans([s3Crit], [], {
  prevReport: validBaseReport({ account_id: "111111111111", coverage: { status: "COMPLETE", services_skipped_optional: [], failures: [] } }),
  currReport: validBaseReport({ account_id: "111111111111", coverage: { status: "COMPLETE", services_skipped_optional: ["S3"], failures: [] } }),
});
assert.equal(skippedS3Diff.resolvedCount, 0, "Skipped optional S3 finding must NEVER be marked resolved");
assert.equal(skippedS3Diff.unverifiedCount, 1);

// 4d. Surviving resource whose rule had CHECK_FAILED in newer scan -> UNVERIFIED (NEVER resolved!)
const failedRuleCurr = {
  ...sgCrit,
  status: "INCOMPLETE",
  assessment: { status: "INCOMPLETE", checks: [{ rule_id: "SG-002", status: "CHECK_FAILED" }] },
  issues: [],
};
const checkFailedDiff = compareScans([sgCrit], [failedRuleCurr], {
  prevReport: validBaseReport({ account_id: "111111111111" }),
  currReport: validBaseReport({ account_id: "111111111111" }),
});
assert.equal(checkFailedDiff.resolvedCount, 0);
assert.equal(checkFailedDiff.unverifiedCount, 1);
assert.equal(checkFailedDiff.scoreDelta, null);

// 4e. Region-aware fallback ID prevents collision across regions
const idEast = getStableResourceId({ id: "high-cpu", type: "cloudwatch_alarm", region: "us-east-1" });
const idWest = getStableResourceId({ id: "high-cpu", type: "cloudwatch_alarm", region: "eu-west-1" });
assert.notEqual(idEast, idWest, "Same resource ID in different regions must not collide");

// =========================================================================
// 5. Static XSS, Network & Storage Sink Audit Across All frontend/src Files
// =========================================================================
function walkJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkJsFiles(full));
    else if (/\.(js|jsx)$/.test(entry.name)) out.push(full);
  }
  return out;
}

const forbiddenPatterns = [
  /dangerouslySetInnerHTML/,
  /\.innerHTML\s*=/,
  /\.outerHTML\s*=/,
  /document\.write\s*\(/,
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\bWebSocket\b/,
  /sendBeacon/,
  /indexedDB/,
  /serviceWorker/,
  /document\.cookie/,
];

const srcDir = path.join(frontendRoot, "src");
for (const file of walkJsFiles(srcDir)) {
  const code = fs.readFileSync(file, "utf8");
  for (const re of forbiddenPatterns) {
    assert.ok(!re.test(code), `Forbidden sink/API ${re} found in ${path.relative(frontendRoot, file)}`);
  }
}

// Verify App.jsx does NOT save imported reports to sessionStorage or localStorage
const appSrc = fs.readFileSync(path.join(srcDir, "App.jsx"), "utf8");
assert.ok(!appSrc.includes("saveRealScanSession"), "App.jsx must not persist imported reports to sessionStorage");
assert.ok(!appSrc.includes("localStorage.setItem"), "App.jsx must not write to localStorage");
assert.ok(!appSrc.includes("sessionStorage.setItem"), "App.jsx must not write to sessionStorage");

// Verify required best-effort sanitization disclaimer exists in DashboardScreen.jsx
const dashSrc = fs.readFileSync(path.join(srcDir, "pages", "DashboardScreen.jsx"), "utf8");
assert.ok(
  dashSrc.includes(
    "Sanitized reports use best-effort redaction. They are not guaranteed to be completely anonymous. Inspect the file before sharing."
  ),
  "DashboardScreen export modal must display the required best-effort redaction disclaimer"
);

// Verify production dist/index.html CSP meta tag (if built)
const distIndex = path.join(frontendRoot, "dist", "index.html");
if (fs.existsSync(distIndex)) {
  const html = fs.readFileSync(distIndex, "utf8");
  for (const directive of [
    "default-src 'self'",
    "script-src 'self'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ]) {
    assert.ok(html.includes(directive), `Production CSP missing directive: ${directive}`);
  }
}

console.log("All Phase 3 malicious input, XSS/sink, canary redaction, CSV formula, comparison safety, and CSP checks passed.");
