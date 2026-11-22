import assert from "node:assert/strict";
import { buildDemoScanData } from "../src/data/demoScanData.js";
import { buildCloudFormationTemplate } from "../src/utils/cloudformationTemplate.js";
import { IAM_POLICY_ACTIONS, SUPPORTED_SERVICES } from "../src/utils/constants.js";
import { computeScore } from "../src/utils/securityScore.js";
import {
  clearAllBrowserData,
  getStableExternalId,
  loadRealScanSession,
  regenerateStableExternalId,
  saveConnectionDetails,
  saveRealScanSession,
} from "../src/utils/connectionStorage.js";

// Minimal in-memory Web Storage polyfill for Node verification
function createMockStorage() {
  const store = new Map();
  return {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
    get size() {
      return store.size;
    },
  };
}

globalThis.localStorage = createMockStorage();
globalThis.sessionStorage = createMockStorage();

// 1. Demo data covers all 10 services, includes CRITICAL/WARNING/UNUSED/INFO/HEALTHY/INCOMPLETE,
//    and is strictly blocked from mixing into real scan storage.
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
saveRealScanSession({ scanResults: demo, storedRoleArn: "arn:aws:iam::000000000000:role/Demo" });
assert.equal(loadRealScanSession(), null, "Demo data must NEVER persist into real scan storage");

// 2. CloudFormation template creates ONLY AWS::IAM::Role and embeds all 35 actions & parameters
assert.equal(IAM_POLICY_ACTIONS.length, 35, "Expected exactly 35 read-only IAM actions (no s3:ListBucket)");
assert.ok(!IAM_POLICY_ACTIONS.includes("s3:ListBucket"), "s3:ListBucket must not be requested");
const yaml = buildCloudFormationTemplate({
  appAccountId: "649655225479",
  externalId: "aws-clarity-stable1234",
});
assert.ok(yaml.includes("Type: AWS::IAM::Role"));
assert.equal((yaml.match(/^\s+Type:\s+AWS::/gm) || []).length, 1, "Template must create ONLY one AWS resource");
assert.ok(yaml.includes('Default: "649655225479"'));
assert.ok(yaml.includes('Default: "aws-clarity-stable1234"'));
for (const action of IAM_POLICY_ACTIONS) {
  assert.ok(yaml.includes(`                  - "${action}"`), `CloudFormation template missing properly indented action ${action}`);
}

// 3. External IDs remain stable across calls/reloads, use 128-bit entropy, and stay scoped per AWS account
const id1 = getStableExternalId("arn:aws:iam::111122223333:role/ReadOnly");
const id2 = getStableExternalId("arn:aws:iam::111122223333:role/ReadOnly");
assert.equal(id1, id2, "External ID must stay stable without regenerating automatically");
assert.match(id1, /^aws-clarity-[0-9a-f]{32}$/, "Generated External ID must contain 128 bits of random hex entropy");
saveConnectionDetails("arn:aws:iam::111122223333:role/ReadOnly", "custom-acct-1-id");
assert.equal(getStableExternalId("arn:aws:iam::111122223333:role/ReadOnly"), "custom-acct-1-id");
const regen = regenerateStableExternalId("arn:aws:iam::111122223333:role/ReadOnly");
assert.notEqual(regen, "custom-acct-1-id");
assert.equal(getStableExternalId("arn:aws:iam::111122223333:role/ReadOnly"), regen);

// 4. Health score is withheld (null / unavailable) whenever scan coverage is incomplete
const incompleteScore = computeScore(demoResources, true);
assert.equal(incompleteScore.isAvailable, false);
assert.equal(incompleteScore.score, null);
assert.equal(incompleteScore.label, "Unavailable");

// Complete scan with INFO-only observations scores 100/100 (INFO deducts 0 points)
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
assert.equal(infoOnlyScore.info, 1);

// 5. Data controls clear all local browser storage cleanly
saveRealScanSession({
  scanResults: { account_id: "111122223333", resources: { vpcs: [] } },
  storedRoleArn: "arn:aws:iam::111122223333:role/ReadOnly",
});
assert.notEqual(loadRealScanSession(), null);
clearAllBrowserData();
assert.equal(loadRealScanSession(), null);
assert.equal(globalThis.localStorage.size, 0);
assert.equal(globalThis.sessionStorage.size, 0);

console.log("All frontend trust, demo isolation, CloudFormation, score, and data-control invariants passed.");
