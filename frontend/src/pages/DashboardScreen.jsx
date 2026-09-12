import { useState, useMemo } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import ResourceTable from "../components/ResourceTable";
import { RESOURCE_TYPE_LABELS, SUPPORTED_REGIONS } from "../utils/constants";
import { computeScore } from "../utils/securityScore";
import { compareScans } from "../utils/scanComparison";
import { scanAccount } from "../services/api";

// ── Severity counter pill ──────────────────────────────────────────────────────
function SeverityPill({ count, label, colorClass, dotClass }) {
  if (count === 0) return null;
  return (
    <div className={`flex items-center gap-1.5 text-[13px] ${colorClass}`}>
      <span className={`inline-block w-2 h-2 rounded-full ${dotClass}`} />
      <span className="font-semibold tabular-nums">{count}</span>
      <span className="text-slate-400 font-normal">{label}</span>
    </div>
  );
}

// ── Score ring ─────────────────────────────────────────────────────────────────
function ScoreRing({ score, label, labelColor }) {
  const r = 28;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const strokeColor =
    score >= 90 ? "#34d399"   // emerald-400
    : score >= 75 ? "#2dd4bf" // teal-400
    : score >= 50 ? "#fbbf24" // amber-400
    : score >= 25 ? "#fb923c" // orange-400
    : "#f87171";              // red-400

  return (
    <div className="flex items-center gap-3">
      <svg width="68" height="68" viewBox="0 0 68 68" className="shrink-0 -rotate-90">
        <circle cx="34" cy="34" r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
        <circle
          cx="34" cy="34" r={r}
          fill="none"
          stroke={strokeColor}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="flex flex-col">
        <span className={`text-3xl font-bold tabular-nums leading-none ${labelColor}`}>
          {score}
        </span>
        <span className={`text-xs font-semibold mt-0.5 ${labelColor}`}>{label}</span>
        <span className="text-[11px] text-slate-500 mt-1 leading-tight">
          Based on checks<br />AWS Clarity performed
        </span>
      </div>
    </div>
  );
}

export default function DashboardScreen({
  scanResults,
  previousScanResults,
  onRescan,
  isLoading,
  scanStatus,
  scanError,
  storedRoleArn,
  storedRegions,
  onStoredRegionsChange,
  onResultsChange,
}) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [healthyExpanded, setHealthyExpanded] = useState(false);
  const [coverageModalOpen, setCoverageModalOpen] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved"); // "resolved" | "stillOpen" | "new"
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanError, setRescanError] = useState(null);

  const coverage = scanResults?.coverage || {};
  const permissionChecks = scanResults?.permission_checks || coverage?.permission_checks || {};
  const scannerStatuses = coverage?.scanner_statuses || [];
  const completedScanners = scannerStatuses.filter(s => s.status === "COMPLETED");
  const failedScanners = scannerStatuses.filter(s => s.status !== "COMPLETED");

  const handleRegionChange = async (newRegions) => {
    if (!storedRoleArn || newRegions.length === 0) return;
    setIsRescanning(true);
    setRescanError(null);
    try {
      const newResults = await scanAccount(storedRoleArn, newRegions);
      onResultsChange(newResults);
      onStoredRegionsChange(newRegions);
    } catch (err) {
      setRescanError(err.message || "Failed to switch regions. Please try again.");
    } finally {
      setIsRescanning(false);
    }
  };

  // ── Flatten previous discovered resources ──────────────────────────────────
  const previousAllResources = useMemo(() => {
    if (!previousScanResults || !previousScanResults.resources) return [];
    return Object.values(previousScanResults.resources).flat().filter(Boolean);
  }, [previousScanResults]);

  // ── Flatten current discovered resources ────────────────────────────────────
  const allResources = useMemo(() => {
    const results = scanResults;
    if (!results || !results.resources) return [];
    return [
      ...(results.resources.ec2_instances         || []),
      ...(results.resources.s3_buckets            || []),
      ...(results.resources.rds_instances         || []),
      ...(results.resources.ebs_volumes           || []),
      ...(results.resources.elastic_ips           || []),
      ...(results.resources.security_groups       || []),
      ...(results.resources.snapshots             || []),
      ...(results.resources.iam_roles             || []),
      ...(results.resources.lambda_functions      || []),
      ...(results.resources.nat_gateways          || []),
      ...(results.resources.load_balancers        || []),
      ...(results.resources.dynamodb_tables       || []),
      ...(results.resources.vpcs                  || []),
      ...(results.resources.auto_scaling_groups   || []),
      ...(results.resources.ecs_clusters          || []),
      ...(results.resources.eks_clusters          || []),
      ...(results.resources.elasticache_clusters  || []),
      ...(results.resources.sqs_queues            || []),
      ...(results.resources.sns_topics            || []),
      ...(results.resources.secrets               || []),
      ...(results.resources.api_gateways          || []),
      ...(results.resources.aurora_clusters       || []),
      ...(results.resources.cloudformation_stacks || []),
      ...(results.resources.eventbridge_rules     || []),
      ...(results.resources.ecr_repositories      || []),
      ...(results.resources.internet_gateways     || []),
      ...(results.resources.cloudwatch_alarms     || []),
      ...(results.resources.redshift_clusters     || []),
    ];
  }, [scanResults]);

  // ── Compare previous vs current scan ────────────────────────────────────────
  const comparison = useMemo(() => {
    return compareScans(previousAllResources, allResources);
  }, [previousAllResources, allResources]);

  // ── Security score ────────────────────────────────────────────────────────────
  const scoreData = useMemo(() => computeScore(allResources), [allResources]);

  // ── Resources sorted by severity (CRITICAL → WARNING → ORPHANED) ─────────────
  const severityPriority = { CRITICAL: 1, WARNING: 2, ORPHANED: 3 };

  const securityResources = useMemo(() =>
    allResources
      .filter(r => r.status && r.status !== "HEALTHY")
      .sort((a, b) => (severityPriority[a.status] || 99) - (severityPriority[b.status] || 99)),
    [allResources]
  );

  const s1Ids = useMemo(() => new Set(securityResources.map(r => r.id)), [securityResources]);

  const hasIssues = securityResources.length > 0;

  // ── "Fix First" — top critical findings (max 5, shown before all others) ──────
  const fixFirstItems = useMemo(() => {
    // Pull every CRITICAL issue across all resources, deduplicated by rule_id
    const seen = new Set();
    const items = [];
    for (const r of securityResources) {
      if (r.status !== "CRITICAL") break; // list is sorted, stop at first non-critical
      for (const issue of (r.issues || [])) {
        if (issue.severity !== "CRITICAL") continue;
        const key = `${issue.rule_id || issue.message}::${r.id}`;
        if (!seen.has(key)) {
          seen.add(key);
          items.push({ resource: r, issue });
        }
      }
      if (items.length >= 5) break;
    }
    return items;
  }, [securityResources]);

  // ── Healthy resources (those with no issues at all) ───────────────────────────
  const healthyResources = useMemo(() =>
    allResources.filter(r => !s1Ids.has(r.id)),
    [allResources, s1Ids]
  );

  // ── CSV Export ────────────────────────────────────────────────────────────────
  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = [
      "Resource Name", "Resource ID", "Resource Type", "Region",
      "Status", "Rule ID", "Severity", "Finding", "Evidence", "Recommended Fix", "Issue Count"
    ];
    const rows = [];
    for (const r of allResources) {
      const issues = r.issues || [];
      const issueCount = issues.length;
      if (issueCount === 0) {
        rows.push([
          escape(r.name),
          escape(r.id),
          escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
          escape(r.region || ""),
          escape("HEALTHY"),
          escape(""),
          escape("HEALTHY"),
          escape("No issues detected"),
          escape(""),
          escape(""),
          escape(0),
        ].join(","));
      } else {
        for (const issue of issues) {
          const evidenceStr = issue.evidence
            ? Object.entries(issue.evidence).map(([k, v]) => `${k}: ${v}`).join(" | ")
            : "";
          rows.push([
            escape(r.name),
            escape(r.id),
            escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
            escape(r.region || ""),
            escape(r.status),
            escape(issue.rule_id || ""),
            escape(issue.severity || ""),
            escape(issue.title || issue.message || ""),
            escape(evidenceStr),
            escape(issue.fix || ""),
            escape(issueCount),
          ].join(","));
        }
      }
    }
    const csvString = [headers.map(escape).join(","), ...rows].join("\n");
    const date = new Date().toISOString().slice(0, 10);
    const filename = `aws-clarity-scan-${scanResults?.account_id || "account"}-${date}.csv`;
    const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="px-4 sm:px-6 lg:px-8 py-4 sm:py-6 max-w-7xl mx-auto w-full flex flex-col gap-[40px]">
        <TopBar
          accountId={scanResults?.account_id || ""}
          region={scanResults?.region || ""}
          scannedAt={scanResults?.scanned_at || ""}
          onRescan={onRescan}
          isLoading={isLoading}
          selectedRegions={storedRegions}
          onRegionChange={handleRegionChange}
          isRescanning={isRescanning}
        />

        {/* Region-switch overlay */}
        {isRescanning && (
          <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
            <svg className="animate-spin w-6 h-6 text-teal-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-gray-200">Switching regions...</p>
              <p className="text-xs text-gray-400 mt-1">This usually takes 10–20 seconds.</p>
            </div>
          </div>
        )}

        {/* Region-switch error banner */}
        {rescanError && (
          <div className="mx-4 sm:mx-6 lg:mx-8 mt-2 px-4 py-3 rounded-lg bg-red-900/40 border border-red-700 text-sm text-red-300 flex items-center justify-between gap-3">
            <span>{rescanError}</span>
            <button onClick={() => setRescanError(null)} className="shrink-0 text-red-400 hover:text-red-200 text-lg leading-none">×</button>
          </div>
        )}

        <div className={isRescanning ? "pointer-events-none opacity-50 select-none" : ""}>

          {/* Empty state */}
          {!isLoading && !scanError && scanResults && (scanResults.summary?.total_resources ?? 0) === 0 && (
            <div className="flex flex-col items-center justify-center gap-4 py-24 text-center px-4">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-gray-600">
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <div>
                <p className="text-base font-medium text-gray-300">No resources found</p>
                <p className="text-sm text-gray-500 mt-1">
                  No active AWS resources were detected in{" "}
                  {scanResults.regions?.length === 1
                    ? scanResults.regions[0]
                    : scanResults.regions?.length > 1
                    ? `${scanResults.regions.length} selected regions`
                    : "the selected region"}.
                </p>
                <p className="text-xs text-gray-600 mt-2">Try selecting a different region using the region selector above.</p>
              </div>
            </div>
          )}

          {/* Main dashboard */}
          {(isLoading || scanError || (scanResults?.summary?.total_resources ?? 0) > 0) && (
            <>

              {/* ── SCAN COVERAGE SUMMARY BAR ───────────────────────────── */}
              {!isLoading && !scanError && scanResults && (
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 flex-1">
                    <div>
                      <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Regions</span>
                      <p className="text-sm font-semibold text-slate-200 mt-0.5">
                        {scanResults.regions?.length === 1 ? scanResults.regions[0] : `${scanResults.regions?.length || 1} Regions`}
                      </p>
                    </div>
                    <div>
                      <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Services Scanned</span>
                      <p className="text-sm font-semibold text-slate-200 mt-0.5">
                        {coverage?.services_scanned?.length ? `${coverage.services_scanned.length} AWS Services` : "Supported Services"}
                      </p>
                    </div>
                    <div>
                      <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Resources Inspected</span>
                      <p className="text-sm font-semibold text-slate-200 mt-0.5">
                        {allResources.length} Resources
                      </p>
                    </div>
                    <div>
                      <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Scan Status</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className={`w-2 h-2 rounded-full ${scanResults.partial ? "bg-amber-400" : "bg-emerald-400"}`} />
                        <span className={`text-sm font-semibold ${scanResults.partial ? "text-amber-400" : "text-emerald-400"}`}>
                          {scanResults.partial ? "Partial Scan" : "Full Coverage"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-slate-800">
                    <button
                      onClick={() => setCoverageModalOpen(true)}
                      className="text-xs text-teal-400 hover:text-teal-300 bg-teal-500/10 border border-teal-500/20 rounded-lg px-3 py-1.5 transition-colors cursor-pointer flex items-center gap-1.5"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="16" x2="12" y2="12" />
                        <line x1="12" y1="8" x2="12.01" y2="8" />
                      </svg>
                      Coverage & Scope
                    </button>
                  </div>
                </div>
              )}

              {/* ── DETAILED PARTIAL SCAN BREAKDOWN ──────────────────────── */}
              {scanResults?.partial === true && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 flex flex-col gap-3">
                  <div className="flex items-start gap-3">
                    <svg className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    <div className="flex-1">
                      <h3 className="text-sm font-semibold text-amber-300">
                        Partial scan — some services could not be inspected
                      </h3>
                      <p className="text-xs text-amber-200/80 mt-1 leading-relaxed">
                        AWS Clarity only claims coverage for services that completed successfully. The findings below reflect only inspected resources.
                      </p>
                    </div>
                  </div>

                  {failedScanners.length > 0 && (
                    <div className="mt-1 rounded-lg bg-slate-900/90 border border-amber-500/20 overflow-hidden divide-y divide-slate-800">
                      <div className="px-3 py-2 bg-slate-900 flex justify-between items-center text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        <span>Skipped / Failed Scanner</span>
                        <span>Reason & Required Permission</span>
                      </div>
                      {failedScanners.map((s, idx) => (
                        <div key={idx} className="px-3 py-2.5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 text-xs">
                          <div className="flex items-center gap-2">
                            <span className="text-amber-400 font-bold">⚠</span>
                            <span className="font-medium text-slate-200">{s.label || s.service}</span>
                            <span className="text-[10px] text-slate-500 font-mono">({s.region || "global"})</span>
                          </div>
                          <div className="text-right sm:text-left flex flex-col sm:items-end">
                            <span className="text-slate-300 text-[11px]">{s.reason || "Missing read permissions"}</span>
                            {s.required_permission && (
                              <span className="text-[10px] text-teal-400 font-mono">Requires: {s.required_permission}</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── SCAN PROGRESS & HISTORY (when previous scan data exists) ─────── */}
              {comparison.hasPrevious && (
                <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-slate-800">
                    <div>
                      <h3 className="text-sm font-semibold text-slate-200">Scan Progress & Comparison</h3>
                      <p className="text-xs text-slate-400">Comparing current scan results against your previous scan.</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-400">
                        Score: <span className="font-semibold text-slate-300">{comparison.previousScore}</span> → <span className="font-semibold text-slate-100">{comparison.currentScore}</span>
                      </span>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
                        comparison.scoreDelta > 0
                          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                          : comparison.scoreDelta < 0
                          ? "text-red-400 bg-red-500/10 border-red-500/20"
                          : "text-slate-400 bg-slate-800 border-slate-700"
                      }`}>
                        {comparison.scoreDelta > 0 ? `+${comparison.scoreDelta} points` : comparison.scoreDelta < 0 ? `${comparison.scoreDelta} points` : "No score change"}
                      </span>
                    </div>
                  </div>

                  {/* Progress Tabs */}
                  <div className="flex items-center gap-2 border-b border-slate-800/80 pb-2 flex-wrap">
                    <button
                      onClick={() => setProgressTab("resolved")}
                      className={`text-xs font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                        progressTab === "resolved"
                          ? "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <span>✓ Resolved</span>
                      <span className="text-[10px] tabular-nums font-mono px-1 rounded bg-slate-800">
                        {comparison.resolvedCount}
                      </span>
                    </button>

                    <button
                      onClick={() => setProgressTab("stillOpen")}
                      className={`text-xs font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                        progressTab === "stillOpen"
                          ? "text-amber-400 bg-amber-500/10 border border-amber-500/20"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <span>⚠ Still Open</span>
                      <span className="text-[10px] tabular-nums font-mono px-1 rounded bg-slate-800">
                        {comparison.stillOpenCount}
                      </span>
                    </button>

                    <button
                      onClick={() => setProgressTab("new")}
                      className={`text-xs font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
                        progressTab === "new"
                          ? "text-cyan-400 bg-cyan-500/10 border border-cyan-500/20"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <span>⚡ Newly Discovered</span>
                      <span className="text-[10px] tabular-nums font-mono px-1 rounded bg-slate-800">
                        {comparison.newCount}
                      </span>
                    </button>
                  </div>

                  {/* Tab Content */}
                  <div className="text-xs space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {progressTab === "resolved" && (
                      comparison.resolvedCount === 0 ? (
                        <p className="text-slate-500 text-[11px] py-1">No previously open findings were resolved in this scan.</p>
                      ) : (
                        comparison.resolved.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-emerald-950/20 border border-emerald-900/30">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-emerald-400 font-bold">✓</span>
                              {item.ruleId && (
                                <span className="text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-1 py-0.5 rounded shrink-0">
                                  {item.ruleId}
                                </span>
                              )}
                              <span className="text-slate-200 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate">({item.resourceName})</span>
                            </div>
                            <span className="text-[10px] text-emerald-400 uppercase font-semibold shrink-0 ml-2">Resolved</span>
                          </div>
                        ))
                      )
                    )}

                    {progressTab === "stillOpen" && (
                      comparison.stillOpenCount === 0 ? (
                        <p className="text-slate-500 text-[11px] py-1">No findings carried over from the previous scan.</p>
                      ) : (
                        comparison.stillOpen.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-amber-950/20 border border-amber-900/30">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-amber-400 font-bold">⚠</span>
                              {item.ruleId && (
                                <span className="text-[10px] font-mono font-bold text-amber-400 bg-amber-500/10 px-1 py-0.5 rounded shrink-0">
                                  {item.ruleId}
                                </span>
                              )}
                              <span className="text-slate-200 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate">({item.resourceName})</span>
                            </div>
                            <span className="text-[10px] text-amber-400 uppercase font-semibold shrink-0 ml-2">Still Open</span>
                          </div>
                        ))
                      )
                    )}

                    {progressTab === "new" && (
                      comparison.newCount === 0 ? (
                        <p className="text-slate-500 text-[11px] py-1">No new findings discovered in this scan.</p>
                      ) : (
                        comparison.newFindings.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-cyan-950/20 border border-cyan-900/30">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-cyan-400 font-bold">⚡</span>
                              {item.ruleId && (
                                <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 px-1 py-0.5 rounded shrink-0">
                                  {item.ruleId}
                                </span>
                              )}
                              <span className="text-slate-200 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate">({item.resourceName})</span>
                            </div>
                            <span className="text-[10px] text-cyan-400 uppercase font-semibold shrink-0 ml-2">New Finding</span>
                          </div>
                        ))
                      )
                    )}
                  </div>
                </div>
              )}

              {/* ── SECURITY POSTURE SECTION ─────────────────────────────────── */}
              <section className="flex flex-col gap-4">

                {isLoading ? (
                  <div className="flex flex-col gap-3">
                    <div className="animate-pulse bg-slate-800 h-[22px] w-36 rounded" />
                    <div className="animate-pulse bg-slate-800 h-16 w-full max-w-sm rounded-xl" />
                  </div>
                ) : scanError ? (
                  <p className="text-[13px] text-slate-400 py-1">
                    Scan failed —{" "}
                    <a href="javascript:void(0)" onClick={() => onRescan()} className="text-blue-400 hover:text-blue-300">retry</a>
                  </p>
                ) : (
                  <>
                    {/* Score row */}
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                      <div className="flex flex-col gap-3">
                        <h2 className="text-[15px] font-medium text-slate-200">
                          {hasIssues ? "Security posture" : "Security posture — all clear"}
                        </h2>

                        <ScoreRing
                          score={scoreData.score}
                          label={scoreData.label}
                          labelColor={scoreData.labelColor}
                        />
                      </div>

                      {/* Severity breakdown */}
                      {allResources.length > 0 && (
                        <div className="flex flex-col gap-2 sm:items-end">
                          <SeverityPill count={scoreData.critical} label="Critical"  colorClass="text-red-400"     dotClass="bg-red-500" />
                          <SeverityPill count={scoreData.warning}  label="Warning"   colorClass="text-amber-400"   dotClass="bg-amber-500" />
                          <SeverityPill count={scoreData.orphaned} label="Orphaned"  colorClass="text-slate-400"   dotClass="bg-slate-500" />
                          <div className="flex items-center gap-1.5 text-[13px] text-emerald-400">
                            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
                            <span className="font-semibold tabular-nums">{scoreData.healthy}</span>
                            <span className="text-slate-400 font-normal">Healthy</span>
                          </div>
                          <span className="text-[11px] text-slate-600 mt-1">
                            {scoreData.totalResources} resources · {scoreData.totalFindings} findings
                          </span>
                        </div>
                      )}
                    </div>

                    {/* ── FIX FIRST — top critical issues ──────────────────── */}
                    {fixFirstItems.length > 0 && (
                      <div className="flex flex-col gap-2 mt-1">
                        <p className="text-[12px] font-semibold uppercase tracking-wider text-red-400">
                          Fix first
                        </p>
                        <div className="flex flex-col divide-y divide-slate-800/60">
                          {fixFirstItems.map(({ resource, issue }, idx) => (
                            <div
                              key={`${issue.rule_id}-${resource.id}-${idx}`}
                              className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1.5 sm:gap-3 py-3 border-l-4 border-l-red-500 pl-3"
                            >
                              <div className="flex flex-col gap-0.5 min-w-0">
                                {/* Rule ID badge + title */}
                                <div className="flex items-center gap-2 flex-wrap">
                                  {issue.rule_id && (
                                    <span className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded shrink-0">
                                      {issue.rule_id}
                                    </span>
                                  )}
                                  <span className="text-[13px] font-medium text-slate-200 leading-snug">
                                    {issue.title || issue.message}
                                  </span>
                                </div>
                                {/* Affected resource */}
                                <span className="text-[12px] text-slate-500">
                                  {RESOURCE_TYPE_LABELS[resource.type] || resource.type} · {resource.name}
                                </span>
                                {/* Plain-English why */}
                                {issue.why && (
                                  <p className="text-[12px] text-slate-400 mt-0.5 leading-relaxed">
                                    {issue.why}
                                  </p>
                                )}
                              </div>
                              <button
                                onClick={() => setSelectedResource(resource)}
                                className="text-[12px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer shrink-0 self-start sm:pt-0.5 whitespace-nowrap"
                              >
                                Inspect →
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* ── Other findings (non-critical or beyond top-5) ─────── */}
                    {securityResources.length > 0 && (
                      <div className="flex flex-col gap-1 mt-1">
                        {fixFirstItems.length > 0 && (
                          <p className="text-[12px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
                            All findings
                          </p>
                        )}
                        <div className="flex flex-col">
                          {securityResources.map((resource) => (
                            <div
                              key={resource.id}
                              className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-2 py-3 w-full border-b-[0.5px] border-slate-800/80 bg-transparent px-3 border-l-4 ${
                                resource.status === "CRITICAL"
                                  ? "border-l-red-500"
                                  : resource.status === "WARNING"
                                  ? "border-l-amber-500"
                                  : "border-l-slate-500"
                              }`}
                            >
                              <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 min-w-0">
                                <span className="text-[14px] font-medium text-slate-200 truncate max-w-[200px] sm:max-w-none">
                                  {resource.name}
                                </span>
                                <span className="text-[12px] text-slate-500 font-normal shrink-0">
                                  {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                                </span>
                                <div className="text-[13px] text-slate-400 truncate min-w-0 sm:ml-2">
                                  {resource.issues && resource.issues.length > 0
                                    ? resource.issues.map(i => i.title || i.message).join(", ")
                                    : "No issues"}
                                </div>
                              </div>
                              <button
                                onClick={() => setSelectedResource(resource)}
                                className="text-[13px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer self-start sm:self-auto shrink-0"
                              >
                                Inspect →
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* All-clear message */}
                    {!hasIssues && allResources.length > 0 && (
                      <div className="flex items-center gap-2 text-[13px] py-1">
                        <svg className="w-[16px] h-[16px] text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                        <span className="text-slate-400 font-normal">
                          No issues detected based on the checks AWS Clarity performed.
                        </span>
                      </div>
                    )}
                  </>
                )}
              </section>

              {/* ── ALL RESOURCES TABLE ─────────────────────────────────────── */}
              <div className="mt-6">
                <ResourceTable
                  resources={allResources}
                  accountId={scanResults?.account_id}
                  onInspect={(resource) => setSelectedResource(resource)}
                />
              </div>

              {/* ── HEALTHY RESOURCES (collapsed by default) ────────────────── */}
              <section className="flex flex-col gap-2">
                {scanError ? (
                  <p className="text-[13px] text-slate-400 py-1">
                    Scan failed —{" "}
                    <a href="javascript:void(0)" onClick={() => onRescan()} className="text-blue-400 hover:text-blue-300">retry</a>
                  </p>
                ) : isLoading ? (
                  <div className="animate-pulse bg-slate-800 h-5 w-72 rounded mt-2" />
                ) : (
                  <>
                    <button
                      onClick={() => setHealthyExpanded(!healthyExpanded)}
                      className="flex items-center text-[13px] text-slate-500 hover:text-slate-400 font-normal bg-transparent border-none p-0 cursor-pointer select-none text-left"
                    >
                      {healthyExpanded ? "↑" : "↓"} {healthyResources.length} healthy resources with no issues
                    </button>

                    {healthyExpanded && (
                      <div className="flex flex-col w-full gap-1.5 mt-2 max-w-xl text-[13px] text-slate-500">
                        {healthyResources.map((resource) => (
                          <div key={resource.id} className="flex justify-between py-0.5">
                            <span className="text-slate-400 truncate pr-4">{resource.name}</span>
                            <span className="text-slate-600 shrink-0">
                              {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </section>

              {/* ── FOOTER / EXPORT ─────────────────────────────────────────── */}
              {!scanError && scanResults && (
                <footer className="flex justify-center pt-4 border-t border-slate-900/60 mt-4">
                  <a
                    href="#"
                    onClick={(e) => { e.preventDefault(); handleExportCSV(); }}
                    className="text-[13px] text-slate-500 hover:text-slate-400 font-normal underline transition-colors cursor-pointer"
                  >
                    Export CSV
                  </a>
                </footer>
              )}

            </>
          )}

        </div>
      </div>

      {/* ── COVERAGE & SCOPE MODAL ────────────────────────────────────────── */}
      {coverageModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-white">Scan Coverage & Limitations</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Complete transparency into what AWS Clarity inspected and what is not covered.
                </p>
              </div>
              <button
                onClick={() => setCoverageModalOpen(false)}
                className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 space-y-5 text-xs">
              {/* Permission Pre-Checks */}
              {Object.keys(permissionChecks).length > 0 && (
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    Permission Pre-Check Status
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {Object.entries(permissionChecks).map(([svc, info]) => {
                      const isOk = info.status === "PASSED";
                      return (
                        <div key={svc} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-2">
                          <span className={`text-sm font-bold ${isOk ? "text-emerald-400" : "text-amber-400"}`}>
                            {isOk ? "✓" : "⚠"}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-slate-200">{svc}</span>
                              <span className={`text-[10px] font-mono px-1 rounded ${isOk ? "text-emerald-400 bg-emerald-500/10" : "text-amber-400 bg-amber-500/10"}`}>
                                {isOk ? "Verified" : "Missing"}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-0.5 leading-tight">{info.capability}</p>
                            {!isOk && (
                              <p className="text-[10px] text-amber-300 font-mono mt-1">Requires: {info.required_permission}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Unsupported services honestly explained */}
              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  What AWS Clarity Does NOT Inspect
                </h4>
                <div className="rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 overflow-hidden">
                  {(coverage?.unsupported_services || [
                    { service: "CloudTrail Log Ingestion", reason: "AWS Clarity performs point-in-time configuration inspection, not continuous event log ingestion." },
                    { service: "AWS WAF / Shield Rules", reason: "Web application firewall rules and DDoS telemetry are not currently inspected." },
                    { service: "Amazon GuardDuty Threat Intel", reason: "GuardDuty automated threat feeds are not queried." },
                    { service: "AWS Cost & Billing Data", reason: "Deliberately removed — AWS Clarity makes zero AWS Cost Explorer API requests." },
                    { service: "Deep Container Vulnerabilities", reason: "ECR repository metadata is scanned; container image CVE layers are not analyzed." }
                  ]).map((item, idx) => (
                    <div key={idx} className="p-2.5 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1">
                      <span className="font-semibold text-slate-300 shrink-0">{item.service}</span>
                      <span className="text-slate-500 text-[11px] sm:text-right">{item.reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Scanned Services breakdown */}
              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Supported Scanners Breakdown ({scannerStatuses.length || 28} scanners)
                </h4>
                <div className="max-h-48 overflow-y-auto rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 pr-1">
                  {scannerStatuses.length > 0 ? (
                    scannerStatuses.map((s, idx) => (
                      <div key={idx} className="p-2 flex items-center justify-between text-[11px]">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className={s.status === "COMPLETED" ? "text-emerald-400" : "text-amber-400"}>
                            {s.status === "COMPLETED" ? "✓" : "⚠"}
                          </span>
                          <span className="text-slate-300 font-medium truncate">{s.label || s.service}</span>
                          <span className="text-[10px] text-slate-600 font-mono">({s.region || "global"})</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400">{s.count ?? 0} found</span>
                          <span className={`text-[10px] px-1 rounded font-mono ${
                            s.status === "COMPLETED"
                              ? "text-emerald-400/80 bg-emerald-500/10"
                              : "text-amber-400/80 bg-amber-500/10"
                          }`}>
                            {s.status}
                          </span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 text-slate-500 text-center">
                      Full read-only inspection performed across all configured AWS services.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
              <button
                onClick={() => setCoverageModalOpen(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-2 rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
