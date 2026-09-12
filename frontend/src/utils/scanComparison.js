/**
 * scanComparison.js
 *
 * Compares two scan result sets (previous vs current) to compute:
 *   - Score change (previousScore -> currentScore, scoreDelta)
 *   - Resolved findings (were in previous scan on resource X with rule Y, but now fixed)
 *   - Still-open findings (were in previous scan and still present)
 *   - Newly discovered findings (were not in previous scan)
 *
 * Strict Rule: Never claim a finding is "resolved" unless comparative data
 * actually proves it was present before and is now absent.
 */

import { computeScore } from "./securityScore.js";

/**
 * @param {Array} prevResources - Flat array of previous scan resources
 * @param {Array} currResources - Flat array of current scan resources
 * @returns {{
 *   hasPrevious: boolean,
 *   previousScore: number,
 *   currentScore: number,
 *   scoreDelta: number,
 *   resolved: Array<{ key: string, resourceId: string, resourceName: string, resourceType: string, ruleId: string, title: string, severity: string }>,
 *   stillOpen: Array<{ key: string, resourceId: string, resourceName: string, resourceType: string, ruleId: string, title: string, severity: string }>,
 *   newFindings: Array<{ key: string, resourceId: string, resourceName: string, resourceType: string, ruleId: string, title: string, severity: string }>,
 *   resolvedCount: number,
 *   stillOpenCount: number,
 *   newCount: number,
 * }}
 */
export function compareScans(prevResources, currResources) {
  if (!prevResources || !Array.isArray(prevResources) || prevResources.length === 0 || !currResources || !Array.isArray(currResources)) {
    return {
      hasPrevious: false,
      previousScore: 0,
      currentScore: computeScore(currResources || []).score,
      scoreDelta: 0,
      resolved: [],
      stillOpen: [],
      newFindings: [],
      resolvedCount: 0,
      stillOpenCount: 0,
      newCount: 0,
    };
  }

  const prevScoreData = computeScore(prevResources);
  const currScoreData = computeScore(currResources);

  // Map previous findings: key -> finding info
  const prevMap = new Map();
  for (const r of prevResources) {
    for (const issue of (r.issues || [])) {
      const ruleId = issue.rule_id || issue.title || issue.message || "UNKNOWN";
      const key = `${r.id}::${ruleId}`;
      prevMap.set(key, {
        key,
        resourceId: r.id,
        resourceName: r.name,
        resourceType: r.type,
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
      });
    }
  }

  // Map current findings: key -> finding info
  const currMap = new Map();
  for (const r of currResources) {
    for (const issue of (r.issues || [])) {
      const ruleId = issue.rule_id || issue.title || issue.message || "UNKNOWN";
      const key = `${r.id}::${ruleId}`;
      currMap.set(key, {
        key,
        resourceId: r.id,
        resourceName: r.name,
        resourceType: r.type,
        ruleId: issue.rule_id || "",
        title: issue.title || issue.message || "Security finding",
        severity: issue.severity || "WARNING",
      });
    }
  }

  const resolved = [];
  const stillOpen = [];
  const newFindings = [];

  // Check resolved & still open
  for (const [key, finding] of prevMap.entries()) {
    if (currMap.has(key)) {
      stillOpen.push(finding);
    } else {
      resolved.push(finding);
    }
  }

  // Check new findings
  for (const [key, finding] of currMap.entries()) {
    if (!prevMap.has(key)) {
      newFindings.push(finding);
    }
  }

  const previousScore = prevScoreData.score;
  const currentScore = currScoreData.score;
  const scoreDelta = currentScore - previousScore;

  return {
    hasPrevious: true,
    previousScore,
    currentScore,
    scoreDelta,
    resolved,
    stillOpen,
    newFindings,
    resolvedCount: resolved.length,
    stillOpenCount: stillOpen.length,
    newCount: newFindings.length,
  };
}
