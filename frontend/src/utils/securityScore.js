/**
 * securityScore.js
 *
 * Computes a deterministic, transparent posture score based on scan findings.
 *   Start at 100.
 *   CRITICAL  -> -10 points per finding
 *   WARNING   -> -4  points per finding
 *   ORPHANED  -> -1  point  per finding
 *   Floored at 0. NOT_ASSESSED resources are neutral.
 */

const DEDUCTIONS = {
  CRITICAL: 10,
  WARNING: 4,
  ORPHANED: 1,
};

export function computeScore(allResources = []) {
  let critical = 0;
  let warning = 0;
  let orphaned = 0;
  let healthy = 0;
  let notAssessed = 0;
  let costAndUnusedFindings = 0;

  for (const r of allResources) {
    const issues = r.issues || [];
    if (issues.length === 0) {
      if (r.status === "HEALTHY" && r.assessment?.status === "ASSESSED") {
        healthy++;
      } else {
        notAssessed++;
      }
      continue;
    }
    for (const issue of issues) {
      const sev = issue.severity || "";
      if (sev === "CRITICAL") critical++;
      else if (sev === "WARNING") warning++;
      else if (sev === "ORPHANED") orphaned++;

      if (issue.category === "Cost Risk" || issue.category === "Unused" || sev === "ORPHANED") {
        costAndUnusedFindings++;
      }
    }
  }

  const totalFindings = critical + warning + orphaned;
  const needsAttention = allResources.filter((r) => (r.issues || []).length > 0).length;
  const totalResources = allResources.length;

  const rawDeduction =
    critical * DEDUCTIONS.CRITICAL +
    warning * DEDUCTIONS.WARNING +
    orphaned * DEDUCTIONS.ORPHANED;

  const score = Math.max(0, Math.min(100, 100 - rawDeduction));

  let label, labelColor;
  if (score >= 90)      { label = "Excellent"; labelColor = "text-emerald-400"; }
  else if (score >= 75) { label = "Good";      labelColor = "text-teal-400"; }
  else if (score >= 50) { label = "Fair";      labelColor = "text-amber-400"; }
  else if (score >= 25) { label = "Poor";      labelColor = "text-orange-400"; }
  else                  { label = "Critical";  labelColor = "text-red-400"; }

  return {
    score,
    critical,
    warning,
    orphaned,
    healthy,
    notAssessed,
    costAndUnusedFindings,
    needsAttention,
    totalResources,
    totalFindings,
    label,
    labelColor,
  };
}
