/**
 * securityScore.js
 *
 * Computes a deterministic, transparent posture score based strictly on verified findings:
 *   Start at 100.
 *   CRITICAL -> -10 points per finding
 *   WARNING  -> -4  points per finding
 *   UNUSED   -> -1  point  per finding
 *   Floored at 0.
 *
 * Resources with INCOMPLETE checks are tracked separately and never credited as HEALTHY.
 */

const DEDUCTIONS = {
  CRITICAL: 10,
  WARNING: 4,
  UNUSED: 1,
};

export function computeScore(allResources = []) {
  let critical = 0;
  let warning = 0;
  let unused = 0;
  let healthy = 0;
  let incomplete = 0;
  let costAndUnusedFindings = 0;

  for (const r of allResources) {
    const issues = r.issues || [];
    if (issues.length === 0) {
      if (r.status === "HEALTHY" && r.assessment?.status === "COMPLETE") {
        healthy++;
      } else {
        incomplete++;
      }
      continue;
    }

    for (const issue of issues) {
      const sev = issue.severity || "";
      if (sev === "CRITICAL") critical++;
      else if (sev === "WARNING") warning++;
      else if (sev === "UNUSED") unused++;

      if (issue.category === "Cost Risk" || issue.category === "Unused" || sev === "UNUSED") {
        costAndUnusedFindings++;
      }
    }
  }

  const totalFindings = critical + warning + unused;
  const needsAttention = allResources.filter((r) => (r.issues || []).length > 0).length;
  const totalResources = allResources.length;

  const rawDeduction =
    critical * DEDUCTIONS.CRITICAL +
    warning * DEDUCTIONS.WARNING +
    unused * DEDUCTIONS.UNUSED;

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
    unused,
    healthy,
    incomplete,
    costAndUnusedFindings,
    needsAttention,
    totalResources,
    totalFindings,
    label,
    labelColor,
  };
}
