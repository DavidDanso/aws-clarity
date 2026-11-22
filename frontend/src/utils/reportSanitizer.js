import { RESOURCE_COLLECTION_KEYS, RESOURCE_TYPE_LABELS } from "./constants.js";

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
const ACCOUNT_ID_RE = /\b\d{12}\b/g;
const ARN_RE = /arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^\s"',}]+/gi;

function redactSensitiveText(text, replacementMap) {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  for (const [secret, alias] of replacementMap.entries()) {
    if (secret && secret.length >= 4 && out.includes(secret)) {
      out = out.split(secret).join(alias);
    }
  }
  out = out.replace(ARN_RE, "[arn-redacted]");
  out = out.replace(ACCOUNT_ID_RE, "000000000000");
  out = out.replace(IPV4_RE, (match) => (match === "0.0.0.0/0" ? match : "[ip-redacted]"));
  return out;
}

/**
 * Produces a share-safe sanitized copy of an AWS Clarity assessment report.
 * Removes AWS Account IDs, Caller ARNs, Resource ARNs, Resource Names/IDs,
 * IP addresses, and raw IAM/network payloads while keeping services, regions,
 * rule IDs, severities, categories, counts, and coverage status intact.
 */
export function sanitizeReportForSharing(report) {
  if (!report || typeof report !== "object") return null;

  const replacementMap = new Map();
  if (report.account_id) replacementMap.set(String(report.account_id), "REDACTED-ACCOUNT");
  if (report.caller_arn) replacementMap.set(String(report.caller_arn), "REDACTED-CALLER-ARN");

  let counter = 1;
  const resourceAliases = new Map();

  for (const key of RESOURCE_COLLECTION_KEYS) {
    for (const r of report.resources?.[key] || []) {
      const alias = `${(r.service || "aws").toLowerCase()}-${(r.type || "resource").replace(/_/g, "-")}-${counter++}`;
      resourceAliases.set(r, alias);
      if (r.id) replacementMap.set(String(r.id), alias);
      if (r.name) replacementMap.set(String(r.name), alias);
      if (r.raw?.arn) replacementMap.set(String(r.raw.arn), `[arn:${alias}]`);
    }
  }

  const sanitizedResources = {};
  for (const key of RESOURCE_COLLECTION_KEYS) {
    sanitizedResources[key] = (report.resources?.[key] || []).map((r) => {
      const alias = resourceAliases.get(r) || "redacted-resource";
      const sanitizedIssues = (r.issues || []).map((issue) => {
        const sanitizedEvidence = {};
        for (const [ek, ev] of Object.entries(issue.evidence || {})) {
          sanitizedEvidence[ek] = redactSensitiveText(
            typeof ev === "object" ? JSON.stringify(ev) : String(ev ?? ""),
            replacementMap
          );
        }
        return {
          rule_id: issue.rule_id,
          severity: issue.severity,
          category: issue.category,
          title: issue.title,
          what_found: redactSensitiveText(issue.what_found || "", replacementMap),
          why: issue.why,
          what_checked: issue.what_checked,
          evidence: sanitizedEvidence,
          fix: redactSensitiveText(issue.fix || "", replacementMap),
          verify: issue.verify,
        };
      });

      return {
        id: alias,
        name: alias,
        type: r.type,
        service: r.service,
        status: r.status,
        region: r.region || "global",
        assessment: r.assessment || null,
        issues: sanitizedIssues,
        raw: { redacted: true },
      };
    });
  }

  const coverage = report.coverage || {};
  const sanitizedFailures = (coverage.failures || []).map((f) => ({
    service: f.service,
    label: redactSensitiveText(String(f.label || ""), replacementMap),
    region: f.region,
    reason: redactSensitiveText(String(f.reason || ""), replacementMap),
    required_permission: f.required_permission,
  }));

  return {
    schema_version: report.schema_version || "aws-clarity-report/v1",
    scanner_version: report.scanner_version || "1.0.0",
    execution_mode: report.execution_mode || "local-cli",
    sanitized_for_sharing: true,
    sanitized_at: new Date().toISOString(),
    status: report.status,
    scan_state: report.scan_state || report.status,
    account_id: "REDACTED-ACCOUNT",
    caller_arn: "REDACTED-CALLER-ARN",
    region: report.region,
    regions: report.regions || [],
    scanned_at: report.scanned_at,
    scan_duration_ms: report.scan_duration_ms,
    partial: report.partial,
    summary: report.summary || {},
    account_advisories: report.account_advisories || [],
    coverage: {
      ...coverage,
      failures: sanitizedFailures,
    },
    resources: sanitizedResources,
  };
}

const CSV_FORMULA_PREFIX_RE = /^[=+\-@\t\r]/;

export function neutralizeCsvCell(val) {
  const str = String(val ?? "");
  const safe = CSV_FORMULA_PREFIX_RE.test(str) ? `'${str}` : str;
  return `"${safe.replace(/"/g, '""')}"`;
}

export function buildInventoryCSV(allResources = [], { sanitized = false } = {}) {
  const escape = neutralizeCsvCell;
  const headers = [
    "Service",
    "Resource Name",
    "Resource ID",
    "Resource Type",
    "Region",
    "Health Status",
    "Category",
    "Rule ID",
    "Severity",
    "Finding",
    "Evidence",
    "Recommended Fix",
    "How to Verify",
  ];
  const rows = [];
  for (const r of allResources) {
    const issues = r.issues || [];
    const displayedStatus =
      r.status === "HEALTHY" && r.assessment?.status !== "COMPLETE"
        ? "INCOMPLETE"
        : r.status || "INCOMPLETE";

    if (issues.length === 0) {
      rows.push(
        [
          escape(r.service || ""),
          escape(r.name),
          escape(r.id),
          escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
          escape(r.region || "global"),
          escape(displayedStatus),
          escape(""),
          escape(""),
          escape(displayedStatus),
          escape(
            displayedStatus === "HEALTHY"
              ? "All applicable checks passed"
              : "Check blocked by API/IAM error"
          ),
          escape(""),
          escape(""),
          escape(""),
        ].join(",")
      );
    } else {
      for (const issue of issues) {
        const evidenceStr = issue.evidence
          ? Object.entries(issue.evidence)
              .map(([k, v]) => `${k}: ${v}`)
              .join(" | ")
          : "";
        rows.push(
          [
            escape(r.service || ""),
            escape(r.name),
            escape(r.id),
            escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
            escape(r.region || "global"),
            escape(displayedStatus),
            escape(issue.category || ""),
            escape(issue.rule_id || ""),
            escape(issue.severity || ""),
            escape(issue.title || issue.message || ""),
            escape(sanitized ? "[see sanitized evidence]" : evidenceStr),
            escape(issue.fix || ""),
            escape(issue.verify || ""),
          ].join(",")
        );
      }
    }
  }
  return [headers.map(escape).join(","), ...rows].join("\n");
}

export function downloadLocalFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
