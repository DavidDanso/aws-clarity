import { RESOURCE_COLLECTION_KEYS, RESOURCE_TYPE_LABELS } from "./constants.js";

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
const IPV6_RE = /\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/\d{1,3})?\b/gi;
const ACCOUNT_ID_RE = /\b\d{12}\b/g;
const ARN_RE = /arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9_-]*:[^\s"',}]+/gi;
const ACCESS_KEY_ID_RE = /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g;
const CREDENTIAL_ASSIGN_RE =
  /(?:aws_secret_access_key|aws_session_token|aws_security_token|SecretAccessKey|SessionToken|SecurityToken)\s*[:=]\s*[^\s,'"}]+|\bFwoGZXIvYXdz[A-Za-z0-9/+=]{16,}/gi;
const AWS_RESOURCE_ID_RE =
  /\b(?:i|vpc|sg|vol|snap|igw|nat|eipalloc|subnet|eni|ami|rtb|acl|vpce|tgw|dopt)-[0-9a-f]{8,17}\b/gi;

function redactSensitiveText(text, replacementMap) {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  // Redact structured credentials, access keys, and full ARNs FIRST so partial substring
  // replacements (like replacing the 12-digit account ID) cannot break ARN matching.
  out = out.replace(CREDENTIAL_ASSIGN_RE, "[credential-redacted]");
  out = out.replace(ACCESS_KEY_ID_RE, "[access-key-redacted]");
  out = out.replace(ARN_RE, "[arn-redacted]");
  const sortedEntries = Array.from(replacementMap.entries()).sort((a, b) => b[0].length - a[0].length);
  for (const [secret, alias] of sortedEntries) {
    if (!secret) continue;
    if (secret.length >= 4 && out.includes(secret)) {
      out = out.split(secret).join(alias);
    } else if (secret.length >= 2 && out === secret) {
      out = alias;
    }
  }
  out = out.replace(AWS_RESOURCE_ID_RE, "[id-redacted]");
  out = out.replace(ACCOUNT_ID_RE, "000000000000");
  out = out.replace(IPV4_RE, (match) => (match === "0.0.0.0/0" ? match : "[ip-redacted]"));
  out = out.replace(IPV6_RE, (match) => {
    if (match === "::/0" || !/[0-9a-f]/i.test(match)) return match;
    return "[ipv6-redacted]";
  });
  return out;
}

function redactAssessment(assessment, replacementMap) {
  if (!assessment || typeof assessment !== "object") return null;
  return {
    status: assessment.status,
    checks: Array.isArray(assessment.checks)
      ? assessment.checks.map((chk) => ({
          rule_id: chk.rule_id,
          status: chk.status,
          ...(chk.reason ? { reason: redactSensitiveText(String(chk.reason), replacementMap) } : {}),
        }))
      : [],
  };
}

/**
 * Produces a best-effort sanitized copy of an AWS Clarity assessment report.
 * Removes AWS Account IDs, Caller ARNs, Resource ARNs, Access Key IDs, Resource Names/IDs,
 * IP addresses/CIDRs (preserving 0.0.0.0/0 and ::/0), and raw AWS payloads while keeping
 * services, regions, rule IDs, severities, categories, counts, and coverage status intact.
 *
 * NOTE: Best-effort redaction is not guaranteed to be completely anonymous—inspect before sharing.
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
      if (r.raw?.function_arn) replacementMap.set(String(r.raw.function_arn), `[arn:${alias}]`);
      if (r.raw?.table_arn) replacementMap.set(String(r.raw.table_arn), `[arn:${alias}]`);
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
          title: redactSensitiveText(issue.title || "", replacementMap),
          what_found: redactSensitiveText(issue.what_found || "", replacementMap),
          why: redactSensitiveText(issue.why || "", replacementMap),
          ...(issue.impact ? { impact: redactSensitiveText(issue.impact, replacementMap) } : {}),
          what_checked: redactSensitiveText(issue.what_checked || "", replacementMap),
          evidence: sanitizedEvidence,
          fix: redactSensitiveText(issue.fix || "", replacementMap),
          verify: redactSensitiveText(issue.verify || "", replacementMap),
        };
      });

      return {
        id: alias,
        name: alias,
        type: r.type,
        service: r.service,
        status: r.status,
        region: r.region || "global",
        assessment: redactAssessment(r.assessment, replacementMap),
        issues: sanitizedIssues,
        raw: { redacted: true },
      };
    });
  }

  const sanitizedAdvisories = (Array.isArray(report.account_advisories) ? report.account_advisories : []).map((adv) => {
    const sanitizedEvidence = {};
    for (const [ek, ev] of Object.entries(adv.evidence || {})) {
      sanitizedEvidence[ek] = redactSensitiveText(
        typeof ev === "object" ? JSON.stringify(ev) : String(ev ?? ""),
        replacementMap
      );
    }
    return {
      rule_id: adv.rule_id,
      severity: adv.severity,
      category: adv.category,
      service: adv.service,
      title: redactSensitiveText(adv.title || "", replacementMap),
      why: redactSensitiveText(adv.why || "", replacementMap),
      ...(adv.impact ? { impact: redactSensitiveText(adv.impact, replacementMap) } : {}),
      ...(Object.keys(sanitizedEvidence).length > 0 ? { evidence: sanitizedEvidence } : {}),
      fix: redactSensitiveText(adv.fix || "", replacementMap),
      verify: redactSensitiveText(adv.verify || "", replacementMap),
    };
  });

  const coverage = report.coverage || {};
  const sanitizedFailures = (coverage.failures || []).map((f) => ({
    service: f.service,
    label: redactSensitiveText(String(f.label || ""), replacementMap),
    region: f.region,
    reason: redactSensitiveText(String(f.reason || ""), replacementMap),
    required_permission: f.required_permission,
  }));
  const sanitizedScannerStatuses = Array.isArray(coverage.scanner_statuses)
    ? coverage.scanner_statuses.map((s) => ({
        ...s,
        ...(s.reason ? { reason: redactSensitiveText(String(s.reason), replacementMap) } : {}),
      }))
    : undefined;
  const sanitizedRegionDiscovery =
    coverage.region_discovery && typeof coverage.region_discovery === "object"
      ? {
          ...coverage.region_discovery,
          ...(coverage.region_discovery.reason
            ? { reason: redactSensitiveText(String(coverage.region_discovery.reason), replacementMap) }
            : {}),
        }
      : coverage.region_discovery;

  return {
    schema_version: report.schema_version || "aws-clarity-report/v1",
    scanner_version: report.scanner_version || "1.0.0",
    execution_mode: report.execution_mode || "local-cli",
    sanitized_for_sharing: true,
    sanitization_notice:
      "Sanitized reports use best-effort redaction. They are not guaranteed to be completely anonymous. Inspect the file before sharing.",
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
    account_advisories: sanitizedAdvisories,
    coverage: {
      ...coverage,
      ...(sanitizedRegionDiscovery !== undefined ? { region_discovery: sanitizedRegionDiscovery } : {}),
      ...(sanitizedScannerStatuses !== undefined ? { scanner_statuses: sanitizedScannerStatuses } : {}),
      failures: sanitizedFailures,
    },
    resources: sanitizedResources,
  };
}

// Neutralize spreadsheet formula prefixes including leading whitespace/control characters
const CSV_FORMULA_PREFIX_RE = /^(?:[\t\r\n]|[ ]*[=+\-@])/;

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
  try {
    link.click();
  } finally {
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
