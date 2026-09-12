/**
 * securityScore.js
 *
 * Computes an explainable security posture score based on actual scan findings.
 *
 * Scoring model:
 *   Start at 100.
 *   Deduct points per finding based on severity.
 *   Score is capped at 0 and rounded to the nearest integer.
 *
 * Deductions (per individual finding, not per resource):
 *   CRITICAL  → -10 points each  (max deduction capped per category so score can't swing wildly)
 *   WARNING   → -4  points each
 *   ORPHANED  → -1  point  each
 *
 * The model is intentionally simple and explainable. The numbers are weights,
 * not absolute thresholds — the goal is to give the user a meaningful signal,
 * not a compliance certification.
 */

const DEDUCTIONS = {
  CRITICAL: 10,
  WARNING:  4,
  ORPHANED: 1,
};

/**
 * @param {Array} allResources - flat array of all scanned resources from DashboardScreen
 * @returns {{
 *   score: number,               // 0–100 integer
 *   critical: number,            // count of CRITICAL findings
 *   warning: number,             // count of WARNING findings
 *   orphaned: number,            // count of ORPHANED findings
 *   healthy: number,             // count of resources with no issues
 *   needsAttention: number,      // count of resources with at least one issue
 *   totalResources: number,
 *   totalFindings: number,
 *   label: string,               // "Excellent" | "Good" | "Fair" | "Poor" | "Critical"
 *   labelColor: string,          // Tailwind text colour class
 * }}
 */
export function computeScore(allResources) {
  let critical = 0;
  let warning  = 0;
  let orphaned = 0;
  let healthy  = 0;

  for (const r of allResources) {
    const issues = r.issues || [];
    if (issues.length === 0) {
      healthy++;
      continue;
    }
    for (const issue of issues) {
      const sev = issue.severity || "";
      if (sev === "CRITICAL")  critical++;
      else if (sev === "WARNING")   warning++;
      else if (sev === "ORPHANED")  orphaned++;
    }
  }

  const totalFindings   = critical + warning + orphaned;
  const needsAttention  = allResources.filter(r => (r.issues || []).length > 0).length;
  const totalResources  = allResources.length;

  const rawDeduction = (critical * DEDUCTIONS.CRITICAL)
                     + (warning  * DEDUCTIONS.WARNING)
                     + (orphaned * DEDUCTIONS.ORPHANED);

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
    needsAttention,
    totalResources,
    totalFindings,
    label,
    labelColor,
  };
}
