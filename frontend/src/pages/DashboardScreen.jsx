import { useState, useMemo } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import ResourceTable from "../components/ResourceTable";
import { RESOURCE_TYPE_LABELS } from "../utils/constants";
import { computeScore } from "../utils/securityScore";
import { compareScans } from "../utils/scanComparison";
import { scanAccount } from "../services/api";

// ── Severity dot + count ──────────────────────────────────────────────────────
function SeverityLine({ count, label, color, dot }) {
  if (count === 0) return null;
  return (
    <div className={`flex items-center gap-2 ${color}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
      <span className="text-[13px] font-semibold tabular-nums leading-none">{count}</span>
      <span className="text-[13px] text-slate-400 font-normal">{label}</span>
    </div>
  );
}

// ── Score ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score, label, labelColor }) {
  const r = 34;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const strokeColor =
    score >= 90 ? "#34d399"
    : score >= 75 ? "#2dd4bf"
    : score >= 50 ? "#fbbf24"
    : score >= 25 ? "#fb923c"
    : "#f87171";

  return (
    <div className="flex items-center gap-5 shrink-0">
      <svg width="80" height="80" viewBox="0 0 80 80" className="-rotate-90 shrink-0">
        <circle cx="40" cy="40" r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
        <circle
          cx="40" cy="40" r={r}
          fill="none"
          stroke={strokeColor}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.7s ease" }}
        />
      </svg>
      <div className="flex flex-col gap-0.5">
        <span className={`text-4xl font-bold tabular-nums leading-none ${labelColor}`}>{score}</span>
        <span className={`text-sm font-semibold mt-1 ${labelColor}`}>{label}</span>
        <span className="text-[11px] text-slate-600 mt-0.5 leading-tight">Security score</span>
      </div>
    </div>
  );
}

// ── Chevron icon ──────────────────────────────────────────────────────────────
function ChevronIcon({ open }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg" width="12" height="12"
      viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      className={`transition-transform duration-200 ${open ? "rotate-180" : ""}`}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
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
  const [coverageModalOpen, setCoverageModalOpen] = useState(false);
  const [comparisonExpanded, setComparisonExpanded] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved");
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanError, setRescanError] = useState(null);

  const coverage = scanResults?.coverage || {};
  const permissionChecks = scanResults?.permission_checks || coverage?.permission_checks || {};
  const scannerStatuses = coverage?.scanner_statuses || [];
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

  // ── Flatten previous resources ─────────────────────────────────────────────
  const previousAllResources = useMemo(() => {
    if (!previousScanResults || !previousScanResults.resources) return [];
    return Object.values(previousScanResults.resources).flat().filter(Boolean);
  }, [previousScanResults]);

  // ── Flatten current resources ──────────────────────────────────────────────
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

  // ── Scan comparison ────────────────────────────────────────────────────────
  const comparison = useMemo(() => {
    return compareScans(previousAllResources, allResources);
  }, [previousAllResources, allResources]);

  // ── Security score ─────────────────────────────────────────────────────────
  const scoreData = useMemo(() => computeScore(allResources), [allResources]);

  // ── Sort by severity ───────────────────────────────────────────────────────
  const severityPriority = { CRITICAL: 1, WARNING: 2, ORPHANED: 3 };

  const securityResources = useMemo(() =>
    allResources
      .filter(r => r.status && r.status !== "HEALTHY")
      .sort((a, b) => (severityPriority[a.status] || 99) - (severityPriority[b.status] || 99)),
    [allResources]
  );

  const hasIssues = securityResources.length > 0;

  // ── Fix First — top critical issues (max 5) ────────────────────────────────
  const fixFirstItems = useMemo(() => {
    const seen = new Set();
    const items = [];
    for (const r of securityResources) {
      if (r.status !== "CRITICAL") break;
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

  // ── CSV Export (11-column comprehensive) ──────────────────────────────────
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
          escape(r.name), escape(r.id),
          escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
          escape(r.region || ""), escape("HEALTHY"),
          escape(""), escape("HEALTHY"),
          escape("No issues detected"), escape(""), escape(""), escape(0),
        ].join(","));
      } else {
        for (const issue of issues) {
          const evidenceStr = issue.evidence
            ? Object.entries(issue.evidence).map(([k, v]) => `${k}: ${v}`).join(" | ")
            : "";
          rows.push([
            escape(r.name), escape(r.id),
            escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
            escape(r.region || ""), escape(r.status),
            escape(issue.rule_id || ""), escape(issue.severity || ""),
            escape(issue.title || issue.message || ""),
            escape(evidenceStr), escape(issue.fix || ""),
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

  // ── Comparison delta label ─────────────────────────────────────────────────
  const deltaLabel =
    comparison.scoreDelta > 0 ? `+${comparison.scoreDelta} pts`
    : comparison.scoreDelta < 0 ? `${comparison.scoreDelta} pts`
    : "no change";
  const deltaColor =
    comparison.scoreDelta > 0 ? "text-emerald-400"
    : comparison.scoreDelta < 0 ? "text-red-400"
    : "text-slate-500";

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="px-4 sm:px-6 lg:px-8 py-4 sm:py-6 max-w-5xl mx-auto w-full">

        {/* TOP BAR */}
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

        {/* Region-switch spinner */}
        {isRescanning && (
          <div className="flex items-center gap-3 py-8 justify-center">
            <svg className="animate-spin w-5 h-5 text-teal-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <div className="text-left">
              <p className="text-sm font-medium text-slate-300">Switching regions…</p>
              <p className="text-xs text-slate-500 mt-0.5">This usually takes 10–20 seconds.</p>
            </div>
          </div>
        )}

        {/* Region-switch error */}
        {rescanError && (
          <div className="mt-3 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800/50 text-sm text-red-300 flex items-center justify-between gap-3">
            <span>{rescanError}</span>
            <button onClick={() => setRescanError(null)} className="shrink-0 text-red-400 hover:text-red-200 text-lg leading-none cursor-pointer">×</button>
          </div>
        )}

        {/* Main content */}
        <div className={`mt-6 ${isRescanning ? "pointer-events-none opacity-40 select-none" : ""}`}>

          {/* SCAN CONTEXT LINE */}
          {!isLoading && !scanError && scanResults && (
            <div className="flex items-center justify-between gap-4 mb-10">
              <p className="text-[12px] text-slate-500 leading-relaxed">
                {allResources.length} resources
                {coverage?.services_scanned?.length
                  ? ` · ${coverage.services_scanned.length} services`
                  : ""}
                {scanResults.regions?.length === 1
                  ? ` · ${scanResults.regions[0]}`
                  : scanResults.regions?.length > 1
                  ? ` · ${scanResults.regions.length} regions`
                  : ""}
                {" · "}
                {scanResults.partial
                  ? <span className="text-amber-400">⚠ Partial scan</span>
                  : <span className="text-emerald-500">Full coverage</span>
                }
              </p>
              <button
                onClick={() => setCoverageModalOpen(true)}
                className="text-[12px] text-slate-500 hover:text-slate-300 shrink-0 cursor-pointer transition-colors"
              >
                Coverage & Scope →
              </button>
            </div>
          )}

          {/* Partial scan inline detail */}
          {!isLoading && !scanError && scanResults?.partial === true && failedScanners.length > 0 && (
            <div className="mb-8 flex flex-col gap-2">
              <p className="text-[11px] text-amber-400/80 font-medium">
                Some services could not be fully inspected. Findings reflect only successfully scanned resources.
              </p>
              <div className="flex flex-col gap-1">
                {failedScanners.slice(0, 4).map((s, idx) => (
                  <p key={idx} className="text-[11px] text-slate-500">
                    <span className="text-amber-400/70">⚠</span>{" "}
                    <span className="text-slate-400">{s.label || s.service}</span>{" "}
                    <span className="text-slate-600 font-mono">({s.region || "global"})</span>
                    {" — "}{s.reason || "missing read permissions"}
                    {s.required_permission && (
                      <span className="text-teal-500/80 font-mono ml-1">[{s.required_permission}]</span>
                    )}
                  </p>
                ))}
                {failedScanners.length > 4 && (
                  <p className="text-[11px] text-slate-600">
                    + {failedScanners.length - 4} more — see Coverage & Scope for full details.
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Empty state */}
          {!isLoading && !scanError && scanResults && (scanResults.summary?.total_resources ?? 0) === 0 && (
            <div className="flex flex-col items-center justify-center gap-4 py-24 text-center px-4">
              <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-slate-700">
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <div>
                <p className="text-base font-medium text-slate-400">No resources found</p>
                <p className="text-sm text-slate-600 mt-1">
                  No active resources were detected in{" "}
                  {scanResults.regions?.length === 1
                    ? scanResults.regions[0]
                    : scanResults.regions?.length > 1
                    ? `${scanResults.regions.length} selected regions`
                    : "the selected region"}.
                </p>
                <p className="text-xs text-slate-700 mt-2">Try a different region using the selector above.</p>
              </div>
            </div>
          )}

          {/* MAIN DASHBOARD */}
          {(isLoading || scanError || (scanResults?.summary?.total_resources ?? 0) > 0) && (
            <div className="flex flex-col gap-12">

              {/* SECURITY OVERVIEW */}
              <section>
                {isLoading ? (
                  <div className="flex flex-col gap-4">
                    <div className="animate-pulse bg-slate-800 h-20 w-48 rounded-xl" />
                    <div className="animate-pulse bg-slate-800 h-4 w-64 rounded" />
                  </div>
                ) : scanError ? (
                  <p className="text-[13px] text-slate-500">
                    Scan failed —{" "}
                    <button onClick={() => onRescan()} className="text-blue-400 hover:text-blue-300 cursor-pointer bg-transparent border-none p-0">
                      retry
                    </button>
                  </p>
                ) : (
                  <div className="flex flex-col gap-6">

                    {/* Score + severity breakdown */}
                    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-6">
                      <ScoreRing
                        score={scoreData.score}
                        label={scoreData.label}
                        labelColor={scoreData.labelColor}
                      />

                      {allResources.length > 0 && (
                        <div className="flex flex-col gap-2.5 sm:items-end sm:pt-1">
                          <SeverityLine count={scoreData.critical} label="Critical"  color="text-red-400"   dot="bg-red-500" />
                          <SeverityLine count={scoreData.warning}  label="Warning"   color="text-amber-400" dot="bg-amber-500" />
                          <SeverityLine count={scoreData.orphaned} label="Orphaned"  color="text-slate-400" dot="bg-slate-500" />
                          <div className="flex items-center gap-2 text-emerald-400">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0 bg-emerald-500" />
                            <span className="text-[13px] font-semibold tabular-nums leading-none">{scoreData.healthy}</span>
                            <span className="text-[13px] text-slate-400 font-normal">Healthy</span>
                          </div>
                          <span className="text-[11px] text-slate-600 mt-0.5">
                            {scoreData.totalResources} resources · {scoreData.totalFindings} findings
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Scan comparison — compact inline */}
                    {comparison.hasPrevious && (
                      <div className="flex flex-col gap-3 pt-1">
                        <div className="flex items-center gap-3 flex-wrap">
                          <span className="text-[12px] text-slate-500">
                            Previous scan:{" "}
                            <span className="text-slate-400 font-medium">{comparison.previousScore}%</span>
                            {" → "}
                            <span className="text-slate-300 font-semibold">{comparison.currentScore}%</span>
                          </span>
                          <span className={`text-[11px] font-semibold ${deltaColor}`}>{deltaLabel}</span>
                          {comparison.resolvedCount > 0 && (
                            <span className="text-[11px] text-emerald-400">✓ {comparison.resolvedCount} resolved</span>
                          )}
                          {comparison.stillOpenCount > 0 && (
                            <span className="text-[11px] text-amber-400">⚠ {comparison.stillOpenCount} still open</span>
                          )}
                          {comparison.newCount > 0 && (
                            <span className="text-[11px] text-cyan-400">⚡ {comparison.newCount} new</span>
                          )}
                          <button
                            onClick={() => setComparisonExpanded(prev => !prev)}
                            className="text-[11px] text-slate-500 hover:text-slate-400 flex items-center gap-1 cursor-pointer bg-transparent border-none p-0"
                          >
                            Details <ChevronIcon open={comparisonExpanded} />
                          </button>
                        </div>

                        {/* Expandable comparison detail */}
                        {comparisonExpanded && (
                          <div className="border border-slate-800 rounded-xl p-4 flex flex-col gap-3 bg-slate-900/60">
                            <div className="flex items-center gap-1 flex-wrap">
                              {[
                                { key: "resolved",  label: "✓ Resolved",        count: comparison.resolvedCount,  activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
                                { key: "stillOpen", label: "⚠ Still Open",       count: comparison.stillOpenCount, activeClass: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
                                { key: "new",       label: "⚡ Newly Discovered", count: comparison.newCount,       activeClass: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" },
                              ].map(tab => (
                                <button
                                  key={tab.key}
                                  onClick={() => setProgressTab(tab.key)}
                                  className={`text-[11px] font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 border ${
                                    progressTab === tab.key
                                      ? tab.activeClass
                                      : "text-slate-400 hover:text-slate-200 border-transparent"
                                  }`}
                                >
                                  {tab.label}
                                  <span className="text-[10px] font-mono tabular-nums px-1 rounded bg-slate-800/80">
                                    {tab.count}
                                  </span>
                                </button>
                              ))}
                            </div>

                            <div className="text-xs space-y-1 max-h-44 overflow-y-auto pr-1">
                              {progressTab === "resolved" && (
                                comparison.resolvedCount === 0
                                  ? <p className="text-slate-600 py-1">No findings resolved in this scan.</p>
                                  : comparison.resolved.map((item, idx) => (
                                    <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-emerald-950/20">
                                      <span className="text-emerald-400 font-bold shrink-0">✓</span>
                                      {item.ruleId && <span className="text-[10px] font-mono text-emerald-400 shrink-0">{item.ruleId}</span>}
                                      <span className="text-slate-300 truncate">{item.title}</span>
                                      <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                                    </div>
                                  ))
                              )}
                              {progressTab === "stillOpen" && (
                                comparison.stillOpenCount === 0
                                  ? <p className="text-slate-600 py-1">No findings carried over from previous scan.</p>
                                  : comparison.stillOpen.map((item, idx) => (
                                    <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-amber-950/20">
                                      <span className="text-amber-400 font-bold shrink-0">⚠</span>
                                      {item.ruleId && <span className="text-[10px] font-mono text-amber-400 shrink-0">{item.ruleId}</span>}
                                      <span className="text-slate-300 truncate">{item.title}</span>
                                      <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                                    </div>
                                  ))
                              )}
                              {progressTab === "new" && (
                                comparison.newCount === 0
                                  ? <p className="text-slate-600 py-1">No new findings discovered.</p>
                                  : comparison.newFindings.map((item, idx) => (
                                    <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-cyan-950/20">
                                      <span className="text-cyan-400 font-bold shrink-0">⚡</span>
                                      {item.ruleId && <span className="text-[10px] font-mono text-cyan-400 shrink-0">{item.ruleId}</span>}
                                      <span className="text-slate-300 truncate">{item.title}</span>
                                      <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                                    </div>
                                  ))
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                )}
              </section>

              {/* FIX FIRST */}
              {!isLoading && !scanError && (
                <section>
                  <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-5">
                    Fix first
                  </p>

                  {fixFirstItems.length > 0 ? (
                    <div className="flex flex-col">
                      {fixFirstItems.map(({ resource, issue }, idx) => (
                        <div
                          key={`${issue.rule_id}-${resource.id}-${idx}`}
                          className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 sm:gap-4 py-4 border-b border-slate-800/60"
                        >
                          <div className="flex flex-col gap-1 min-w-0">
                            <div className="flex items-center gap-2.5 flex-wrap">
                              <span className="text-[10px] font-semibold uppercase tracking-wider text-red-400">
                                Critical
                              </span>
                              {issue.rule_id && (
                                <span className="text-[10px] font-mono text-slate-500">{issue.rule_id}</span>
                              )}
                              <span className="text-[13px] font-medium text-slate-200 leading-snug">
                                {issue.title || issue.message}
                              </span>
                            </div>
                            <span className="text-[12px] text-slate-500">
                              {RESOURCE_TYPE_LABELS[resource.type] || resource.type} · {resource.name}
                            </span>
                            {issue.why && (
                              <p className="text-[12px] text-slate-400 leading-relaxed mt-0.5 max-w-prose">
                                {issue.why}
                              </p>
                            )}
                          </div>
                          <button
                            onClick={() => setSelectedResource(resource)}
                            className="text-[12px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer shrink-0 self-start sm:pt-0.5 whitespace-nowrap transition-colors"
                          >
                            Inspect →
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : !hasIssues && allResources.length > 0 ? (
                    <div className="flex items-center gap-2 py-1">
                      <svg className="w-3.5 h-3.5 text-emerald-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      <span className="text-[13px] text-slate-500">
                        Nothing urgent found based on the checks AWS Clarity performed.
                      </span>
                    </div>
                  ) : null}
                </section>
              )}

              {/* RESOURCE INVENTORY */}
              {!isLoading && !scanError && (
                <section>
                  <div className="flex items-center justify-between mb-5">
                    <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                      All resources
                    </p>
                    {scanResults && (
                      <button
                        onClick={handleExportCSV}
                        className="text-[12px] text-slate-500 hover:text-slate-400 cursor-pointer bg-transparent border-none p-0 transition-colors"
                      >
                        Export CSV
                      </button>
                    )}
                  </div>

                  <ResourceTable
                    resources={allResources}
                    accountId={scanResults?.account_id}
                    onInspect={(resource) => setSelectedResource(resource)}
                  />
                </section>
              )}

              {/* Loading skeleton */}
              {isLoading && (
                <div className="flex flex-col gap-4">
                  {[...Array(6)].map((_, i) => (
                    <div key={i} className="animate-pulse bg-slate-800/60 h-10 rounded-lg" style={{ opacity: 1 - i * 0.12 }} />
                  ))}
                </div>
              )}

            </div>
          )}
        </div>
      </div>

      {/* COVERAGE & SCOPE MODAL */}
      {coverageModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto flex flex-col">
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

            <div className="p-5 space-y-5 text-xs">
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
                    { service: "Deep Container Vulnerabilities", reason: "ECR repository metadata is scanned; container image CVE layers are not analyzed." },
                  ]).map((item, idx) => (
                    <div key={idx} className="p-2.5 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1">
                      <span className="font-semibold text-slate-300 shrink-0">{item.service}</span>
                      <span className="text-slate-500 text-[11px] sm:text-right">{item.reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Supported Scanners ({scannerStatuses.length || 28} scanners)
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

      {/* DETAIL DRAWER */}
      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
