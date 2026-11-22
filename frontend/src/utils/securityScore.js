/**
 * securityScore.js
 *
 * Computes a deterministic, transparent operational posture score from verified findings:
 *   Start at 100.
 *   CRITICAL -> -10 points per finding
 *   WARNING  -> -4  points per finding
 *   UNUSED   -> -1  point  per finding
 *   INFO     ->  0  points (informational review only; never penalizes score)
 *   Floored at 0.
 *
 * TRUST GUARDRAIL:
 * If required scan coverage is incomplete (any failed service, unreachable region,
 * missing permission, or incomplete resource check), the health score is intentionally
 * withheld (`isAvailable: false`, `score: null`) so partial scans are never mistaken
 * for a complete 100/100 healthy account.
 */

const DEDUCTIONS = {
  CRITICAL: 10,
  WARNING: 4,
  UNUSED: 1,
};

export function normalizeCategory(category, severity) {
  if (category === "Security Risk" || category === "Security") return "Security Risk";
  if (
    category === "Potential Cost Waste" ||
    category === "Cost Risk" ||
    category === "Unused" ||
    severity === "UNUSED"
  ) {
    return "Potential Cost Waste";
  }
  return "Operational Concern";
}

export function computeScore(allResources = [], isIncompleteCoverage = false) {
  let critical = 0;
  let warning = 0;
  let unused = 0;
  let info = 0;
  let healthy = 0;
  let incomplete = 0;
  let securityRisks = 0;
  let operationalConcerns = 0;
  let potentialCostWaste = 0;

  for (const r of allResources) {
    const issues = r.issues || [];
    const hasActionable = issues.some((i) => i?.severity !== "INFO");

    if (r.status === "INCOMPLETE" || r.assessment?.status === "INCOMPLETE") {
      incomplete++;
    } else if (!hasActionable && r.status === "HEALTHY" && r.assessment?.status === "COMPLETE") {
      healthy++;
    }

    for (const issue of issues) {
      const sev = issue.severity || "";
      if (sev === "CRITICAL") critical++;
      else if (sev === "WARNING") warning++;
      else if (sev === "UNUSED") unused++;
      else if (sev === "INFO") info++;

      const cat = normalizeCategory(issue.category, sev);
      if (cat === "Security Risk") securityRisks++;
      else if (cat === "Potential Cost Waste") potentialCostWaste++;
      else operationalConcerns++;
    }
  }

  const totalFindings = critical + warning + unused;
  const needsAttention = allResources.filter((r) =>
    (r.issues || []).some((i) => i?.severity !== "INFO")
  ).length;
  const totalResources = allResources.length;
  const isAvailable = !isIncompleteCoverage && incomplete === 0;

  const rawDeduction =
    critical * DEDUCTIONS.CRITICAL +
    warning * DEDUCTIONS.WARNING +
    unused * DEDUCTIONS.UNUSED;

  const rawScore = Math.max(0, Math.min(100, 100 - rawDeduction));
  const score = isAvailable ? rawScore : null;

  let label, labelColor;
  if (!isAvailable) {
    label = "Unavailable";
    labelColor = "text-orange-300";
  } else if (rawScore >= 90) {
    label = "Excellent";
    labelColor = "text-emerald-400";
  } else if (rawScore >= 75) {
    label = "Good";
    labelColor = "text-teal-400";
  } else if (rawScore >= 50) {
    label = "Fair";
    labelColor = "text-amber-400";
  } else if (rawScore >= 25) {
    label = "Poor";
    labelColor = "text-orange-400";
  } else {
    label = "Critical";
    labelColor = "text-red-400";
  }

  return {
    isAvailable,
    score,
    critical,
    warning,
    unused,
    info,
    healthy,
    incomplete,
    securityRisks,
    operationalConcerns,
    potentialCostWaste,
    costAndUnusedFindings: potentialCostWaste,
    needsAttention,
    totalResources,
    totalFindings,
    label,
    labelColor,
  };
}
