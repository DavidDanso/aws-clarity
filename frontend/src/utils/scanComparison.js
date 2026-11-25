/**
 * scanComparison.js
 *
 * Compares two scan result sets (previous vs current) to compute:
 *   - Stable Resource Identity: ARN, function_arn, or ${type}::${id}
 *   - Resource Lifecycle Tracking:
 *       - newly discovered resources
 *       - removed resources
 *       - resource status changes (e.g. CRITICAL -> HEALTHY)
 *   - Security Finding Changes:
 *       - resolved findings
 *       - still-open findings
 *       - newly discovered findings
 *   - Score change (previousScore -> currentScore, scoreDelta)
 *   - Meaningful Change Flag: boolean indicating if anything actually changed
 *   - Per-Resource History Map for deep inspection
 *
 * Strict Rules:
 *   - Never identify resources solely by name (display names can change/duplicate).
 *   - Never claim a finding is "resolved" unless comparative data proves it was present before and is now absent.
 *   - Never fabricate historical data for scans that happened before the feature existed.
 */

import { computeScore } from "./securityScore.js";

/**
 * Derives a stable, globally unique identifier for an AWS resource.
 * Prefers standard ARNs when present; falls back to composite `${type}::${id}`.
 *
 * @param {Object} resource
 * @returns {string}
 */
export function getStableResourceId(resource) {
  if (!resource) return "";
  const raw = resource.raw || {};
  if (raw.arn && typeof raw.arn === "string") return raw.arn;
  if (raw.Arn && typeof raw.Arn === "string") return raw.Arn;
  if (raw.ARN && typeof raw.ARN === "string") return raw.ARN;
  if (raw.function_arn && typeof raw.function_arn === "string") return raw.function_arn;
  if (raw.FunctionArn && typeof raw.FunctionArn === "string") return raw.FunctionArn;
  if (raw.role_arn && typeof raw.role_arn === "string") return raw.role_arn;
  if (raw.RoleArn && typeof raw.RoleArn === "string") return raw.RoleArn;

  // Fallback composite key using type, region, and resource ID (avoids cross-region name/ID collisions)
  const resType = resource.type || "unknown";
  const resRegion = resource.region || "global";
  const resId = resource.id || resource.name || "unknown";
  return `${resType}::${resRegion}::${resId}`;
}

/**
 * Extracts a stable finding key composed of stable resource ID + rule ID.
 *
 * @param {string} stableResourceId
 * @param {Object} issue
 * @returns {string}
 */
export function getStableFindingKey(stableResourceId, issue) {
  const ruleId = issue.rule_id || issue.title || issue.message || "UNKNOWN";
  return `${stableResourceId}::${ruleId}`;
}

function isReportIncomplete(report, explicitFlag) {
  if (typeof explicitFlag === "boolean") return explicitFlag;
  if (!report || typeof report !== "object") return false;
  return (
    report.coverage?.status === "INCOMPLETE" ||
    report.partial === true ||
    (report.coverage?.failures || []).length > 0
  );
}

/**
 * Compares two scans and calculates comprehensive resource and finding diffs.
 *
 * Safety invariants:
 * - Refuses to compare reports from two different non-empty AWS accounts.
 * - Never marks a previous finding "resolved" if its resource/service/region was
 *   incomplete, failed, or skipped-optional in the newer scan (tracks under `unverified`).
 * - Withholds `scoreDelta` (`null`) whenever either scan has incomplete coverage.
 */
export function compareScans(prevResources, currResources, options = {}) {
  const prevReport = options?.prevReport || null;
  const currReport = options?.currReport || null;
  const prevIncomplete = isReportIncomplete(prevReport, options?.prevIncomplete);
  const currIncomplete = isReportIncomplete(currReport, options?.currIncomplete);
  const prevAdvisories = prevReport?.account_advisories || [];
  const currAdvisories = currReport?.account_advisories || [];

  const emptyResult = (overrides = {}) => ({
    hasPrevious: false,
    isComparable: true,
    incomparableReason: "",
    warnings: [],
    previousScore: null,
    currentScore: computeScore(currResources || [], currIncomplete, currAdvisories).score,
    scoreDelta: null,
    newResources: [],
    removedResources: [],
    statusChanges: [],
    resolved: [],
    unverified: [],
    stillOpen: [],
    newFindings: [],
    newResourcesCount: 0,
    removedResourcesCount: 0,
    statusChangesCount: 0,
    resolvedCount: 0,
    unverifiedCount: 0,
    stillOpenCount: 0,
    newCount: 0,
    hasMeaningfulChanges: false,
    resourceHistoryMap: new Map(),
    ...overrides,
  });

  if (
    !prevResources ||
    !Array.isArray(prevResources) ||
    prevResources.length === 0 ||
    !currResources ||
    !Array.isArray(currResources)
  ) {
    return emptyResult();
  }

  // Guard 1: Refuse silent cross-account comparison
  const prevAccountId = typeof prevReport?.account_id === "string" ? prevReport.account_id.trim() : "";
  const currAccountId = typeof currReport?.account_id === "string" ? currReport.account_id.trim() : "";
  if (
    prevAccountId &&
    currAccountId &&
    prevAccountId !== "REDACTED-ACCOUNT" &&
    currAccountId !== "REDACTED-ACCOUNT" &&
    prevAccountId !== currAccountId
  ) {
    return emptyResult({
      hasPrevious: true,
      isComparable: false,
      incomparableReason:
        "These two reports belong to different AWS accounts and cannot be compared reliably. Findings from the earlier account are not marked resolved.",
    });
  }

  const prevScoreData = computeScore(prevResources, prevIncomplete, prevAdvisories);
  const currScoreData = computeScore(currResources, currIncomplete, currAdvisories);

  // Extract newer scan failure/skip context so disappearing resources are never falsely marked resolved
  const currSkippedServices = new Set(currReport?.coverage?.services_skipped_optional || []);
  const currFailedRegions = new Set(currReport?.coverage?.regions_failed || []);
  const currFailedServices = new Set(
    (currReport?.coverage?.failures || []).map((f) => f?.service).filter(Boolean)
  );
  for (const s of currReport?.coverage?.scanner_statuses || []) {
    if (s?.status && s.status !== "COMPLETED" && s.status !== "SKIPPED_OPTIONAL") {
      if (s.service) currFailedServices.add(s.service);
      if (s.region && s.region !== "global") currFailedRegions.add(s.region);
    }
  }

  const warnings = [];
  if (prevIncomplete || currIncomplete) {
    warnings.push(
      "At least one compared scan had incomplete coverage; findings whose service, region, or check did not complete in the newer scan are held as unverified rather than marked resolved, and score delta is withheld."
    );
  }
  if (currSkippedServices.size > 0) {
    warnings.push(
      `Optional service(s) skipped in the newer scan (${Array.from(currSkippedServices).join(", ")}) cannot be verified as resolved.`
    );
  }

  // 1. Build stable resource maps: stableId -> resource (ignoring malformed entries without IDs)
  const prevResourceMap = new Map();
  for (const r of prevResources) {
    if (!r || typeof r !== "object" || (!r.id && !r.raw?.arn)) continue;
    const stableId = getStableResourceId(r);
    if (!prevResourceMap.has(stableId)) prevResourceMap.set(stableId, r);
  }

  const currResourceMap = new Map();
  for (const r of currResources) {
    if (!r || typeof r !== "object" || (!r.id && !r.raw?.arn)) continue;
    const stableId = getStableResourceId(r);
    if (!currResourceMap.has(stableId)) currResourceMap.set(stableId, r);
  }

  // 2. Identify resource additions, removals, and status changes
  const newResources = [];
  const removedResources = [];
  const statusChanges = [];

  for (const [stableId, currR] of currResourceMap.entries()) {
    if (!prevResourceMap.has(stableId)) {
      newResources.push(currR);
    } else {
      const prevR = prevResourceMap.get(stableId);
      if (prevR.status !== currR.status) {
        statusChanges.push({
          stableId,
          resourceName: currR.name || currR.id,
          resourceType: currR.type,
          previousStatus: prevR.status || "INCOMPLETE",
          currentStatus: currR.status || "INCOMPLETE",
          resolvedCount: 0,
          newCount: 0,
        });
      }
    }
  }

  for (const [stableId, prevR] of prevResourceMap.entries()) {
    if (!currResourceMap.has(stableId)) {
      removedResources.push(prevR);
    }
  }

  // 3. Map previous and current findings using stable resource identifiers
  const prevFindingMap = new Map();
  for (const [stableId, r] of prevResourceMap.entries()) {
    for (const issue of Array.isArray(r.issues) ? r.issues : []) {
      if (!issue || typeof issue !== "object") continue;
      const key = getStableFindingKey(stableId, issue);
      prevFindingMap.set(key, {
        key,
        stableResourceId: stableId,
        resourceId: r.id,
        resourceName: r.name || r.id,
        resourceType: r.type,
        service: r.service || issue.service || "",
        region: r.region || "global",
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
        issue,
      });
    }
  }

  const currFindingMap = new Map();
  for (const [stableId, r] of currResourceMap.entries()) {
    for (const issue of Array.isArray(r.issues) ? r.issues : []) {
      if (!issue || typeof issue !== "object") continue;
      const key = getStableFindingKey(stableId, issue);
      currFindingMap.set(key, {
        key,
        stableResourceId: stableId,
        resourceId: r.id,
        resourceName: r.name || r.id,
        resourceType: r.type,
        service: r.service || issue.service || "",
        region: r.region || "global",
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
        issue,
      });
    }
  }

  const resolved = [];
  const unverified = [];
  const stillOpen = [];
  const newFindings = [];

  // Check resolved vs unverified vs still open findings
  for (const [key, finding] of prevFindingMap.entries()) {
    if (currFindingMap.has(key)) {
      stillOpen.push(finding);
      continue;
    }

    const currR = currResourceMap.get(finding.stableResourceId);
    if (currR) {
      const ruleFailed = (currR.assessment?.checks || []).some(
        (c) => c?.rule_id === finding.ruleId && c?.status === "CHECK_FAILED"
      );
      if (currR.status === "INCOMPLETE" || currR.assessment?.status === "INCOMPLETE" || ruleFailed) {
        unverified.push({
          ...finding,
          reason: "Resource check was incomplete or failed in the newer scan.",
        });
      } else {
        resolved.push(finding);
      }
    } else {
      // Resource disappeared from newer scan: ONLY treat as resolved if newer scan cleanly covered its service & region
      const svcSkipped = finding.service && currSkippedServices.has(finding.service);
      const svcFailed = finding.service && currFailedServices.has(finding.service);
      const regFailed = finding.region && currFailedRegions.has(finding.region);
      if (currIncomplete || svcSkipped || svcFailed || regFailed) {
        unverified.push({
          ...finding,
          reason: svcSkipped
            ? `${finding.service} checks were skipped in the newer scan.`
            : "Newer scan coverage was incomplete for this resource's service or region.",
        });
      } else {
        resolved.push(finding);
      }
    }
  }

  // Check new findings
  for (const [key, finding] of currFindingMap.entries()) {
    if (!prevFindingMap.has(key)) {
      newFindings.push(finding);
    }
  }

  // 4. Build per-resource history lookup map
  const resourceHistoryMap = new Map();

  for (const [stableId, currR] of currResourceMap.entries()) {
    const prevR = prevResourceMap.get(stableId);
    const isNew = !prevR;
    const previousStatus = prevR ? (prevR.status || "INCOMPLETE") : null;
    const currentStatus = currR.status || "INCOMPLETE";
    const statusChanged = prevR ? prevR.status !== currR.status : false;

    const resResolved = resolved.filter((f) => f.stableResourceId === stableId);
    const resUnverified = unverified.filter((f) => f.stableResourceId === stableId);
    const resNew = newFindings.filter((f) => f.stableResourceId === stableId);
    const resStillOpen = stillOpen.filter((f) => f.stableResourceId === stableId);

    resourceHistoryMap.set(stableId, {
      hasHistory: true,
      isNew,
      isRemoved: false,
      previousStatus,
      currentStatus,
      statusChanged,
      resolvedIssues: resResolved,
      unverifiedIssues: resUnverified,
      newIssues: resNew,
      stillOpenIssues: resStillOpen,
    });
  }

  for (const [stableId, prevR] of prevResourceMap.entries()) {
    if (!currResourceMap.has(stableId)) {
      resourceHistoryMap.set(stableId, {
        hasHistory: true,
        isNew: false,
        isRemoved: true,
        previousStatus: prevR.status || "INCOMPLETE",
        currentStatus: "REMOVED",
        statusChanged: true,
        resolvedIssues: [],
        unverifiedIssues: unverified.filter((f) => f.stableResourceId === stableId),
        newIssues: [],
        stillOpenIssues: [],
      });
    }
  }

  const previousScore = prevScoreData.isAvailable ? prevScoreData.score : null;
  const currentScore = currScoreData.isAvailable ? currScoreData.score : null;
  const scoreDelta =
    previousScore !== null && currentScore !== null ? currentScore - previousScore : null;

  const hasMeaningfulChanges =
    newResources.length > 0 ||
    removedResources.length > 0 ||
    statusChanges.length > 0 ||
    resolved.length > 0 ||
    newFindings.length > 0;

  return {
    hasPrevious: true,
    isComparable: true,
    incomparableReason: "",
    warnings,
    previousScore,
    currentScore,
    scoreDelta,
    newResources,
    removedResources,
    statusChanges,
    resolved,
    unverified,
    stillOpen,
    newFindings,
    newResourcesCount: newResources.length,
    removedResourcesCount: removedResources.length,
    statusChangesCount: statusChanges.length,
    resolvedCount: resolved.length,
    unverifiedCount: unverified.length,
    stillOpenCount: stillOpen.length,
    newCount: newFindings.length,
    hasMeaningfulChanges,
    resourceHistoryMap,
  };
}
