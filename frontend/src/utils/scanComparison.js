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

  // Fallback composite key using type and resource ID
  const resType = resource.type || "unknown";
  const resId = resource.id || resource.name || "unknown";
  return `${resType}::${resId}`;
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

/**
 * Compares two scans and calculates comprehensive resource and finding diffs.
 *
 * @param {Array} prevResources - Flat array of previous scan resources
 * @param {Array} currResources - Flat array of current scan resources
 * @returns {{
 *   hasPrevious: boolean,
 *   previousScore: number,
 *   currentScore: number,
 *   scoreDelta: number,
 *   newResources: Array<Object>,
 *   removedResources: Array<Object>,
 *   statusChanges: Array<{
 *     stableId: string,
 *     resourceName: string,
 *     resourceType: string,
 *     previousStatus: string,
 *     currentStatus: string,
 *     resolvedCount: number,
 *     newCount: number
 *   }>,
 *   resolved: Array<Object>,
 *   stillOpen: Array<Object>,
 *   newFindings: Array<Object>,
 *   newResourcesCount: number,
 *   removedResourcesCount: number,
 *   statusChangesCount: number,
 *   resolvedCount: number,
 *   stillOpenCount: number,
 *   newCount: number,
 *   hasMeaningfulChanges: boolean,
 *   resourceHistoryMap: Map<string, {
 *     hasHistory: boolean,
 *     isNew: boolean,
 *     isRemoved: boolean,
 *     previousStatus: string|null,
 *     currentStatus: string,
 *     statusChanged: boolean,
 *     resolvedIssues: Array<Object>,
 *     newIssues: Array<Object>,
 *     stillOpenIssues: Array<Object>
 *   }>
 * }}
 */
export function compareScans(prevResources, currResources) {
  if (
    !prevResources ||
    !Array.isArray(prevResources) ||
    prevResources.length === 0 ||
    !currResources ||
    !Array.isArray(currResources)
  ) {
    return {
      hasPrevious: false,
      previousScore: 0,
      currentScore: computeScore(currResources || []).score,
      scoreDelta: 0,
      newResources: [],
      removedResources: [],
      statusChanges: [],
      resolved: [],
      stillOpen: [],
      newFindings: [],
      newResourcesCount: 0,
      removedResourcesCount: 0,
      statusChangesCount: 0,
      resolvedCount: 0,
      stillOpenCount: 0,
      newCount: 0,
      hasMeaningfulChanges: false,
      resourceHistoryMap: new Map(),
    };
  }

  const prevScoreData = computeScore(prevResources);
  const currScoreData = computeScore(currResources);

  // 1. Build stable resource maps: stableId -> resource
  const prevResourceMap = new Map();
  for (const r of prevResources) {
    const stableId = getStableResourceId(r);
    prevResourceMap.set(stableId, r);
  }

  const currResourceMap = new Map();
  for (const r of currResources) {
    const stableId = getStableResourceId(r);
    currResourceMap.set(stableId, r);
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
          previousStatus: prevR.status || "HEALTHY",
          currentStatus: currR.status || "HEALTHY",
          resolvedCount: 0, // will populate below
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
  for (const r of prevResources) {
    const stableId = getStableResourceId(r);
    for (const issue of (r.issues || [])) {
      const ruleId = issue.rule_id || issue.title || issue.message || "UNKNOWN";
      const key = getStableFindingKey(stableId, issue);
      prevFindingMap.set(key, {
        key,
        stableResourceId: stableId,
        resourceId: r.id,
        resourceName: r.name,
        resourceType: r.type,
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
        issue,
      });
    }
  }

  const currFindingMap = new Map();
  for (const r of currResources) {
    const stableId = getStableResourceId(r);
    for (const issue of (r.issues || [])) {
      const ruleId = issue.rule_id || issue.title || issue.message || "UNKNOWN";
      const key = getStableFindingKey(stableId, issue);
      currFindingMap.set(key, {
        key,
        stableResourceId: stableId,
        resourceId: r.id,
        resourceName: r.name,
        resourceType: r.type,
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
        issue,
      });
    }
  }

  const resolved = [];
  const stillOpen = [];
  const newFindings = [];

  // Check resolved and still open findings
  for (const [key, finding] of prevFindingMap.entries()) {
    if (currFindingMap.has(key)) {
      stillOpen.push(finding);
    } else {
      resolved.push(finding);
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

  // For current resources
  for (const [stableId, currR] of currResourceMap.entries()) {
    const prevR = prevResourceMap.get(stableId);
    const isNew = !prevR;
    const previousStatus = prevR ? (prevR.status || "HEALTHY") : null;
    const currentStatus = currR.status || "HEALTHY";
    const statusChanged = prevR ? prevR.status !== currR.status : false;

    // Filter findings relevant to this resource
    const resResolved = resolved.filter(f => f.stableResourceId === stableId);
    const resNew = newFindings.filter(f => f.stableResourceId === stableId);
    const resStillOpen = stillOpen.filter(f => f.stableResourceId === stableId);

    resourceHistoryMap.set(stableId, {
      hasHistory: true,
      isNew,
      isRemoved: false,
      previousStatus,
      currentStatus,
      statusChanged,
      resolvedIssues: resResolved,
      newIssues: resNew,
      stillOpenIssues: resStillOpen,
    });
  }

  // Also include removed resources in history map if inspected
  for (const [stableId, prevR] of prevResourceMap.entries()) {
    if (!currResourceMap.has(stableId)) {
      resourceHistoryMap.set(stableId, {
        hasHistory: true,
        isNew: false,
        isRemoved: true,
        previousStatus: prevR.status || "HEALTHY",
        currentStatus: "REMOVED",
        statusChanged: true,
        resolvedIssues: [],
        newIssues: [],
        stillOpenIssues: [],
      });
    }
  }

  const previousScore = prevScoreData.score;
  const currentScore = currScoreData.score;
  const scoreDelta = currentScore - previousScore;

  const hasMeaningfulChanges =
    newResources.length > 0 ||
    removedResources.length > 0 ||
    statusChanges.length > 0 ||
    resolved.length > 0 ||
    newFindings.length > 0;

  return {
    hasPrevious: true,
    previousScore,
    currentScore,
    scoreDelta,
    newResources,
    removedResources,
    statusChanges,
    resolved,
    stillOpen,
    newFindings,
    newResourcesCount: newResources.length,
    removedResourcesCount: removedResources.length,
    statusChangesCount: statusChanges.length,
    resolvedCount: resolved.length,
    stillOpenCount: stillOpen.length,
    newCount: newFindings.length,
    hasMeaningfulChanges,
    resourceHistoryMap,
  };
}
