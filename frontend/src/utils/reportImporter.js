import { RESOURCE_COLLECTION_KEYS } from "./constants.js";

export const MAX_REPORT_BYTES = 25 * 1024 * 1024; // 25 MB safety limit
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const CREDENTIAL_KEYS_NORMALIZED = new Set([
  "secretaccesskey",
  "sessiontoken",
  "securitytoken",
  "awssecretaccesskey",
  "awssessiontoken",
  "awssecuritytoken",
  "accesskeysecret",
  "awssecretkey",
]);
const CREDENTIAL_VALUE_RE =
  /(?:aws_secret_access_key|aws_session_token|aws_security_token|SecretAccessKey|SessionToken|SecurityToken)\s*[:=]\s*[^\s,'"}]+|\bASIA[0-9A-Z]{16}\b|\bFwoGZXIvYXdz[A-Za-z0-9/+=]{16,}/i;
const ALLOWED_STATUSES = new Set(["CRITICAL", "WARNING", "UNUSED", "HEALTHY", "INCOMPLETE"]);
const ALLOWED_SEVERITIES = new Set(["CRITICAL", "WARNING", "UNUSED", "INFO"]);

function stripControlChars(str, maxLen = 4096) {
  let out = "";
  const limit = Math.min(str.length, maxLen);
  for (let i = 0; i < limit; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 0 && code <= 8) || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127) {
      continue;
    }
    out += str[i];
  }
  return str.length > maxLen ? `${out}…` : out;
}

export function sanitizeImportedFileName(name) {
  return stripControlChars(String(name || ""), 128).trim();
}

/**
 * Recursively clones untrusted JSON data while:
 * - Dropping prototype-pollution keys (`__proto__`, `constructor`, `prototype`)
 * - Stripping control characters and bounding string lengths
 * - Detecting accidental credential fields and secret/session-token string patterns
 */
function sanitizeUntrustedValue(value, depth = 0, state = { foundCredentialField: false, maxDepthExceeded: false }) {
  if (depth > 16) {
    state.maxDepthExceeded = true;
    return null;
  }
  if (value === null || value === undefined) return value;
  if (typeof value === "boolean" || typeof value === "number") {
    return Number.isFinite(value) || typeof value === "boolean" ? value : null;
  }
  if (typeof value === "string") {
    if (CREDENTIAL_VALUE_RE.test(value)) {
      state.foundCredentialField = true;
    }
    return stripControlChars(value, 4096);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20000).map((item) => sanitizeUntrustedValue(item, depth + 1, state));
  }
  if (typeof value === "object") {
    const clean = Object.create(null);
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      if (CREDENTIAL_KEYS_NORMALIZED.has(k.toLowerCase().replace(/[_-]/g, ""))) {
        state.foundCredentialField = true;
        continue;
      }
      clean[k] = sanitizeUntrustedValue(v, depth + 1, state);
    }
    // Convert back to a normal plain object without copying forbidden keys
    return { ...clean };
  }
  return null;
}

function validateAndNormalizeResource(item, collectionKey) {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    throw new Error(`Malformed report: resources.${collectionKey} contains a non-object entry.`);
  }
  if (typeof item.id !== "string" || !item.id.trim()) {
    throw new Error(`Malformed report: resources.${collectionKey} contains a resource with a missing or invalid id.`);
  }
  if (item.status !== undefined && (typeof item.status !== "string" || !ALLOWED_STATUSES.has(item.status))) {
    throw new Error(`Malformed report: resources.${collectionKey} contains an unsupported status value.`);
  }
  if (item.issues !== undefined && !Array.isArray(item.issues)) {
    throw new Error(`Malformed report: resources.${collectionKey} has a non-array issues field.`);
  }

  const normalizedIssues = [];
  for (const issue of item.issues || []) {
    if (!issue || typeof issue !== "object" || Array.isArray(issue)) {
      throw new Error(`Malformed report: resources.${collectionKey} contains an invalid finding object.`);
    }
    if (typeof issue.severity !== "string" || !ALLOWED_SEVERITIES.has(issue.severity)) {
      throw new Error(`Malformed report: resources.${collectionKey} contains a finding with an unsupported severity.`);
    }
    normalizedIssues.push(issue);
  }

  // Never allow a resource without complete assessment metadata to claim HEALTHY
  const assessmentStatus = item.assessment && typeof item.assessment === "object" ? item.assessment.status : null;
  const resolvedStatus =
    !item.status || (item.status === "HEALTHY" && assessmentStatus !== "COMPLETE")
      ? "INCOMPLETE"
      : item.status;

  return {
    ...item,
    id: item.id,
    name: typeof item.name === "string" && item.name ? item.name : item.id,
    region: typeof item.region === "string" && item.region ? item.region : "global",
    status: resolvedStatus,
    issues: normalizedIssues,
  };
}

/**
 * Safely parses and validates a local AWS Clarity JSON report completely in-memory.
 * Never executes code, never makes network requests, and treats all imported fields
 * as untrusted data.
 */
export function parseLocalAssessmentReport(rawText, fileSizeBytes = null) {
  if (typeof fileSizeBytes === "number" && fileSizeBytes > MAX_REPORT_BYTES) {
    throw new Error(
      "Report file exceeds the 25 MB local browser safety limit. " +
        "Why: Large files can freeze browser memory. " +
        "Next: Re-run `aws-clarity scan` with specific regions (e.g. `--regions us-east-1,eu-west-1`) and `--compact`."
    );
  }
  if (typeof rawText !== "string" || !rawText.trim()) {
    throw new Error(
      "The selected file is empty. " +
        "Why: The scan may have been interrupted before writing output. " +
        "Next: Re-run `aws-clarity scan --output aws-clarity-report.json` and select the newly written file."
    );
  }
  if (rawText.length > MAX_REPORT_BYTES) {
    throw new Error(
      "Report content exceeds the 25 MB local browser safety limit. " +
        "Next: Re-run `aws-clarity scan` for a subset of regions (e.g. `--regions us-east-1`) with `--compact`."
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new Error(
      "Invalid JSON file. Why: The file is not valid JSON (for example, a CSV export or truncated file). " +
        "Next: Select the `.json` file generated by `aws-clarity scan --output aws-clarity-report.json`."
    );
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      "Unsupported report format: root JSON value must be an object. " +
        "Next: Import a report file generated by `aws-clarity scan --output aws-clarity-report.json`."
    );
  }

  const scanState = { foundCredentialField: false, maxDepthExceeded: false };
  const safe = sanitizeUntrustedValue(parsed, 0, scanState);

  if (scanState.foundCredentialField) {
    throw new Error(
      "Blocked import: this file appears to contain AWS credential fields (SecretAccessKey / SessionToken / temporary STS credentials). " +
        "Why: AWS Clarity refuses credential files to prevent accidental secret handling in the browser. " +
        "Next: Select an assessment report generated by `aws-clarity scan` instead."
    );
  }

  if (safe.is_demo === true) {
    throw new Error(
      "Demo fixtures cannot be imported as real AWS account assessments. " +
        "Next: Use 'Explore Live Demo' on the home screen to inspect sample data."
    );
  }

  if (!safe.resources || typeof safe.resources !== "object" || Array.isArray(safe.resources)) {
    throw new Error(
      "This JSON file is missing the required `resources` inventory object. " +
        "Why: It may be an IAM policy file or another tool's JSON output. " +
        "Next: Generate a report with `aws-clarity scan --output aws-clarity-report.json` and import that file."
    );
  }

  // Normalize recognized resource collections, reject malformed items, and deduplicate duplicates
  const normalizedResources = {};
  let recognizedCollectionCount = 0;
  for (const key of RESOURCE_COLLECTION_KEYS) {
    if (key in safe.resources) {
      if (!Array.isArray(safe.resources[key])) {
        throw new Error(`Malformed report: resources.${key} must be a list.`);
      }
      recognizedCollectionCount++;
      const seenKeys = new Set();
      const deduped = [];
      for (const rawItem of safe.resources[key]) {
        const normalized = validateAndNormalizeResource(rawItem, key);
        const rawArn = normalized.raw && typeof normalized.raw === "object" && typeof normalized.raw.arn === "string"
          ? normalized.raw.arn
          : "";
        const dedupKey = rawArn || `${normalized.type || key}::${normalized.region}::${normalized.id}`;
        if (seenKeys.has(dedupKey)) continue;
        seenKeys.add(dedupKey);
        deduped.push(normalized);
      }
      normalizedResources[key] = deduped;
    } else {
      normalizedResources[key] = [];
    }
  }

  if (recognizedCollectionCount === 0) {
    throw new Error(
      "No recognized AWS Clarity resource collections were found in this JSON file."
    );
  }

  const coverage = safe.coverage && typeof safe.coverage === "object" && !Array.isArray(safe.coverage)
    ? safe.coverage
    : {};
  const regions = Array.isArray(safe.regions)
    ? safe.regions.filter((r) => typeof r === "string")
    : Array.isArray(coverage.regions_scanned)
    ? coverage.regions_scanned.filter((r) => typeof r === "string")
    : [];

  const accountAdvisories = Array.isArray(safe.account_advisories)
    ? safe.account_advisories.filter(
        (a) => a && typeof a === "object" && !Array.isArray(a) && ALLOWED_SEVERITIES.has(a.severity)
      )
    : [];

  return {
    ...safe,
    is_demo: false,
    imported_locally: true,
    account_id: typeof safe.account_id === "string" ? safe.account_id : "",
    caller_arn: typeof safe.caller_arn === "string" ? safe.caller_arn : "",
    scanned_at: typeof safe.scanned_at === "string" ? safe.scanned_at : "",
    regions,
    coverage,
    resources: normalizedResources,
    account_advisories: accountAdvisories,
  };
}
