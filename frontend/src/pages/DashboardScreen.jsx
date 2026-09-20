import { useState, useMemo } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import ResourceTable from "../components/ResourceTable";
import { RESOURCE_TYPE_LABELS } from "../utils/constants";
import { computeScore } from "../utils/securityScore";
import { compareScans, getStableResourceId } from "../utils/scanComparison";
import { scanAccount } from "../services/api";
import { SECURITY_CHECKS, evaluateCheckStatus } from "../utils/securityChecksCatalog";

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
      <svg width="76" height="76" viewBox="0 0 80 80" className="-rotate-90 shrink-0">
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
      <div className="flex flex-col">
        <span className={`text-4xl font-bold tabular-nums leading-none tracking-tight ${labelColor}`}>{score}</span>
        <span className={`text-sm font-semibold mt-1.5 leading-none ${labelColor}`}>{label}</span>
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
  const [scoreModalOpen, setScoreModalOpen] = useState(false);
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [catalogFilter, setCatalogFilter] = useState("all");
  const [catalogSearch, setCatalogSearch] = useState("");
  const [comparisonExpanded, setComparisonExpanded] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved");
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

  // ── Evaluated Security Checks Catalog ─────────────────────────────────────
  const evaluatedChecks = useMemo(() => {
    return SECURITY_CHECKS.map(check => ({
      ...check,
      eval: evaluateCheckStatus(check, allResources),
    }));
  }, [allResources]);

  const filteredChecks = useMemo(() => {
    let list = evaluatedChecks;
    if (catalogFilter === "violated") {
      list = list.filter(c => c.eval.status === "VIOLATED");
    } else if (catalogFilter === "passed") {
      list = list.filter(c => c.eval.status === "PASSED");
    } else if (catalogFilter === "na") {
      list = list.filter(c => c.eval.status === "NOT_APPLICABLE");
    }

    if (catalogSearch.trim()) {
      const q = catalogSearch.toLowerCase().trim();
      list = list.filter(c =>
        c.name.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q) ||
        c.service.toLowerCase().includes(q) ||
        c.whatItChecks.toLowerCase().includes(q)
      );
    }
    return list;
  }, [evaluatedChecks, catalogFilter, catalogSearch]);

  const checkCounts = useMemo(() => {
    return {
      total: evaluatedChecks.length,
      violated: evaluatedChecks.filter(c => c.eval.status === "VIOLATED").length,
      passed: evaluatedChecks.filter(c => c.eval.status === "PASSED").length,
      na: evaluatedChecks.filter(c => c.eval.status === "NOT_APPLICABLE").length,
    };
  }, [evaluatedChecks]);

  // ── Sort resources with issues by severity ─────────────────────────────────
  const severityPriority = { CRITICAL: 1, WARNING: 2, ORPHANED: 3 };

  const securityResources = useMemo(() =>
    allResources
      .filter(r => r.status && r.status !== "HEALTHY")
      .sort((a, b) => (severityPriority[a.status] || 99) - (severityPriority[b.status] || 99)),
    [allResources]
  );

  // ── Top Attention Item(s) — focused action area ────────────────────────────
  const topAttentionItems = useMemo(() => {
    const seen = new Set();
    const items = [];
    // Prioritize critical issues
    for (const r of securityResources) {
      for (const issue of (r.issues || [])) {
        if (issue.severity === "CRITICAL") {
          const key = `${issue.rule_id || issue.message}::${r.id}`;
          if (!seen.has(key)) {
            seen.add(key);
            items.push({ resource: r, issue });
          }
        }
      }
    }
    if (items.length > 0) {
      return items.slice(0, 2);
    }
    // Fall back to top warning if no critical issues exist
    for (const r of securityResources) {
      for (const issue of (r.issues || [])) {
        if (issue.severity === "WARNING") {
          const key = `${issue.rule_id || issue.message}::${r.id}`;
          if (!seen.has(key)) {
            seen.add(key);
            items.push({ resource: r, issue });
          }
        }
      }
    }
    return items.slice(0, 1);
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

  const regionDisplay = scanResults?.regions?.length === 1
    ? scanResults.regions[0]
    : scanResults?.regions?.length > 1
    ? `${scanResults.regions.length} regions`
    : scanResults?.region || "us-east-1";

  const servicesCount = coverage?.services_scanned?.length || completedScanners.length || 0;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="px-4 sm:px-6 lg:px-8 py-4 sm:py-6 max-w-5xl mx-auto w-full">

        {/* ── TOP CONTEXT: Compact TopBar ─────────────────────────────────── */}
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
        <div className={`mt-8 sm:mt-12 ${isRescanning ? "pointer-events-none opacity-40 select-none" : ""}`}>

          {/* Empty state */}
          {!isLoading && !scanError && scanResults && (scanResults.summary?.total_resources ?? 0) === 0 && (
            <div className="flex flex-col items-center justify-center gap-4 py-24 text-center px-4">
              <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-slate-700">
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <div>
                <p className="text-base font-medium text-slate-400">No resources found</p>
                <p className="text-sm text-slate-600 mt-1">
                  No active resources were detected in {regionDisplay}.
                </p>
                <p className="text-xs text-slate-700 mt-2">Try a different region using the selector above.</p>
              </div>
            </div>
          )}

          {/* MAIN DASHBOARD: Three-Level Progressive Flow */}
          {(isLoading || scanError || (scanResults?.summary?.total_resources ?? 0) > 0) && (
            <div className="flex flex-col space-y-12 sm:space-y-16">

              {/* ──────────────────────────────────────────────────────────── */}
              {/* LEVEL 1 — SECURITY STATUS                                   */}
              {/* ──────────────────────────────────────────────────────────── */}
              <section>
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-6">
                  Security Status
                </p>

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
                  <div className="flex flex-col gap-5">
                    {/* Score + Breakdown line */}
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
                      <ScoreRing
                        score={scoreData.score}
                        label={scoreData.label}
                        labelColor={scoreData.labelColor}
                      />

                      {allResources.length > 0 && (
                        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
                          {scoreData.critical > 0 && (
                            <div className="flex items-center gap-1.5 text-red-400 font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                              <span>{scoreData.critical} Critical</span>
                            </div>
                          )}
                          {scoreData.warning > 0 && (
                            <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
                              <span>{scoreData.warning} Warning{scoreData.warning > 1 ? "s" : ""}</span>
                            </div>
                          )}
                          {scoreData.orphaned > 0 && (
                            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-slate-500 shrink-0" />
                              <span>{scoreData.orphaned} Orphaned</span>
                            </div>
                          )}
                          <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                            <span>{scoreData.healthy} Healthy</span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Supporting context line */}
                    <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap pt-1">
                      <span>Based on checks AWS Clarity performed.</span>
                      <span>·</span>
                      <button
                        onClick={() => setScoreModalOpen(true)}
                        className="hover:text-slate-300 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                      >
                        How is this calculated?
                      </button>
                      <span>·</span>
                      <button
                        onClick={() => setCatalogModalOpen(true)}
                        className="hover:text-slate-300 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                      >
                        Security checks catalog ({SECURITY_CHECKS.length} checks)
                      </button>
                      <span>·</span>
                      <button
                        onClick={() => setCoverageModalOpen(true)}
                        className="hover:text-slate-300 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                      >
                        {scanResults?.partial
                          ? "⚠ Partial scan · View coverage details"
                          : `Coverage: ${servicesCount} services checked · View scope`}
                      </button>

                      {comparison.hasPrevious && (
                        <>
                          <span>·</span>
                          <span className="text-slate-400">
                            Previous scan: {comparison.previousScore}% → {comparison.currentScore}%
                          </span>
                          <span className={`font-semibold ${deltaColor}`}>{deltaLabel}</span>
                          {comparison.hasMeaningfulChanges && (
                            <span className="text-slate-400">
                              ({[
                                comparison.resolvedCount > 0 && `${comparison.resolvedCount} resolved`,
                                comparison.newCount > 0 && `${comparison.newCount} new issue${comparison.newCount > 1 ? "s" : ""}`,
                                comparison.newResourcesCount > 0 && `${comparison.newResourcesCount} new resource${comparison.newResourcesCount > 1 ? "s" : ""}`,
                                comparison.removedResourcesCount > 0 && `${comparison.removedResourcesCount} removed`,
                                comparison.statusChangesCount > 0 && `${comparison.statusChangesCount} status change${comparison.statusChangesCount > 1 ? "s" : ""}`,
                              ].filter(Boolean).join(", ")})
                            </span>
                          )}
                          <button
                            onClick={() => setComparisonExpanded(prev => !prev)}
                            className="hover:text-slate-300 flex items-center gap-1 cursor-pointer bg-transparent border-none p-0 text-slate-400"
                          >
                            Details <ChevronIcon open={comparisonExpanded} />
                          </button>
                        </>
                      )}
                    </div>

                    {/* Expandable scan comparison detail panel */}
                    {comparisonExpanded && comparison.hasPrevious && (
                      <div className="mt-3 border border-slate-800/80 rounded-xl p-4 flex flex-col gap-3 bg-slate-900/40">
                        <div className="flex items-center gap-1 flex-wrap">
                          {[
                            { key: "resolved",       label: "✓ Resolved Issues",    count: comparison.resolvedCount,         activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
                            { key: "stillOpen",      label: "⚠ Still Open",         count: comparison.stillOpenCount,        activeClass: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
                            { key: "new",            label: "⚡ New Issues",        count: comparison.newCount,              activeClass: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" },
                            { key: "newResources",   label: "📦 New Resources",     count: comparison.newResourcesCount,     activeClass: "text-sky-400 bg-sky-500/10 border-sky-500/20" },
                            { key: "removedResources", label: "🗑 Removed Resources", count: comparison.removedResourcesCount, activeClass: "text-rose-400 bg-rose-500/10 border-rose-500/20" },
                            { key: "statusChanges",  label: "🔄 Status Changes",    count: comparison.statusChangesCount,    activeClass: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20" },
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
                          {progressTab === "newResources" && (
                            comparison.newResourcesCount === 0
                              ? <p className="text-slate-600 py-1">No new resources discovered since last scan.</p>
                              : comparison.newResources.map((item, idx) => (
                                <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-sky-950/20">
                                  <div className="flex items-center gap-2 truncate">
                                    <span className="text-sky-400 font-bold shrink-0">📦</span>
                                    <span className="text-[10px] font-mono text-sky-400 shrink-0 uppercase">{item.type}</span>
                                    <span className="text-slate-300 truncate">{item.name || item.id}</span>
                                  </div>
                                  <span className={`text-[10px] font-semibold uppercase ${STATUS_COLOR[item.status] || "text-slate-400"}`}>
                                    {item.status}
                                  </span>
                                </div>
                              ))
                          )}
                          {progressTab === "removedResources" && (
                            comparison.removedResourcesCount === 0
                              ? <p className="text-slate-600 py-1">No resources removed since last scan.</p>
                              : comparison.removedResources.map((item, idx) => (
                                <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-rose-950/20">
                                  <div className="flex items-center gap-2 truncate">
                                    <span className="text-rose-400 font-bold shrink-0">🗑</span>
                                    <span className="text-[10px] font-mono text-rose-400 shrink-0 uppercase">{item.type}</span>
                                    <span className="text-slate-300 truncate">{item.name || item.id}</span>
                                  </div>
                                  <span className="text-[10px] text-slate-500 font-mono">Removed</span>
                                </div>
                              ))
                          )}
                          {progressTab === "statusChanges" && (
                            comparison.statusChangesCount === 0
                              ? <p className="text-slate-600 py-1">No resource status changes detected.</p>
                              : comparison.statusChanges.map((item, idx) => (
                                <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-indigo-950/20">
                                  <div className="flex items-center gap-2 truncate">
                                    <span className="text-indigo-400 font-bold shrink-0">🔄</span>
                                    <span className="text-[10px] font-mono text-indigo-400 shrink-0 uppercase">{item.resourceType}</span>
                                    <span className="text-slate-300 truncate">{item.resourceName}</span>
                                  </div>
                                  <div className="flex items-center gap-1.5 shrink-0 text-[11px] font-mono">
                                    <span className={STATUS_COLOR[item.previousStatus] || "text-slate-400"}>{item.previousStatus}</span>
                                    <span className="text-slate-500">→</span>
                                    <span className={STATUS_COLOR[item.currentStatus] || "text-slate-400"}>{item.currentStatus}</span>
                                  </div>
                                </div>
                              ))
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* ──────────────────────────────────────────────────────────── */}
              {/* LEVEL 2 — WHAT NEEDS ATTENTION                              */}
              {/* ──────────────────────────────────────────────────────────── */}
              {!isLoading && !scanError && (
                <section>
                  <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-4">
                    Needs Attention
                  </p>

                  {topAttentionItems.length > 0 ? (
                    <div className="divide-y divide-slate-800/60 border-y border-slate-800/60">
                      {topAttentionItems.map(({ resource, issue }, idx) => (
                        <div
                          key={`${issue.rule_id}-${resource.id}-${idx}`}
                          className="py-4 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3"
                        >
                          <div className="flex flex-col gap-1 min-w-0">
                            <div className="flex items-center gap-2.5 flex-wrap">
                              <span className={`text-[11px] font-semibold uppercase tracking-wider ${
                                issue.severity === "CRITICAL" ? "text-red-400" : "text-amber-400"
                              }`}>
                                {issue.severity === "CRITICAL" ? "Critical" : "Warning"}
                              </span>
                              {issue.rule_id && (
                                <span className="text-[11px] font-mono text-slate-500">{issue.rule_id}</span>
                              )}
                              <span className="text-[13px] font-medium text-slate-200">
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
                            className="text-[12px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer shrink-0 sm:pt-0.5 self-start whitespace-nowrap transition-colors"
                          >
                            Inspect →
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2.5 py-2 text-slate-400 text-[13px]">
                      <svg className="w-4 h-4 text-emerald-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      <span>Nothing urgent found based on checks performed.</span>
                    </div>
                  )}
                </section>
              )}

              {/* ──────────────────────────────────────────────────────────── */}
              {/* LEVEL 3 — RESOURCE WORKSPACE                                */}
              {/* ──────────────────────────────────────────────────────────── */}
              {!isLoading && !scanError && (
                <section>
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                        All Resources
                      </p>
                      <p className="text-[12px] text-slate-500 mt-0.5">
                        {allResources.length} resources · {regionDisplay}
                      </p>
                    </div>
                    {scanResults && (
                      <button
                        onClick={handleExportCSV}
                        className="text-[12px] text-slate-500 hover:text-slate-300 cursor-pointer bg-transparent border-none p-0 transition-colors"
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

      {/* ── COVERAGE & SCOPE MODAL ────────────────────────────────────────── */}
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

              {/* Scope Summary Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <p className="text-[10px] uppercase font-semibold text-slate-500">Region(s)</p>
                  <p className="text-xs font-bold text-slate-200 mt-0.5 truncate">{coverage?.regions_scanned?.join(", ") || regionDisplay}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <p className="text-[10px] uppercase font-semibold text-slate-500">Services Checked</p>
                  <p className="text-xs font-bold text-teal-400 mt-0.5">{servicesCount}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <p className="text-[10px] uppercase font-semibold text-slate-500">Resources Inspected</p>
                  <p className="text-xs font-bold text-slate-200 mt-0.5">{coverage?.resources_inspected ?? allResources.length}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <p className="text-[10px] uppercase font-semibold text-slate-500">Findings Detected</p>
                  <p className="text-xs font-bold text-amber-400 mt-0.5">{coverage?.findings_detected ?? 0}</p>
                </div>
              </div>

              {/* Core Permission Pre-Check Status */}
              {Object.keys(permissionChecks).length > 0 && (
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    Core Permission Status
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

              {/* Supported Scanners Breakdown */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Scanners Breakdown ({scannerStatuses.length || 28} registered)
                  </h4>
                  <span className="text-[10px] text-slate-500">
                    {completedScanners.length} completed{failedScanners.length > 0 ? ` · ${failedScanners.length} failed` : ""}
                  </span>
                </div>
                <div className="max-h-48 overflow-y-auto rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 pr-1">
                  {scannerStatuses.length > 0 ? (
                    scannerStatuses.map((s, idx) => {
                      const isOk = s.status === "COMPLETED";
                      return (
                        <div key={idx} className="p-2 flex items-center justify-between text-[11px]">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className={isOk ? "text-emerald-400" : "text-amber-400"}>
                              {isOk ? "✓" : "⚠"}
                            </span>
                            <span className="text-slate-300 font-medium truncate">{s.label || s.service}</span>
                            <span className="text-[10px] text-slate-600 font-mono">({s.region || "global"})</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {isOk ? (
                              <span className="text-slate-400">{s.count ?? 0} found</span>
                            ) : (
                              <span className="text-amber-400/90 text-[10px] truncate max-w-[140px]">{s.reason || "Skipped"}</span>
                            )}
                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                              isOk
                                ? "text-emerald-400/80 bg-emerald-500/10"
                                : "text-amber-400/80 bg-amber-500/10"
                            }`}>
                              {s.status}
                            </span>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="p-3 text-slate-500 text-center">
                      Read-only configuration inspection performed across configured AWS services.
                    </div>
                  )}
                </div>
              </div>

              {/* What AWS Clarity Does NOT Inspect */}
              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  What AWS Clarity Does NOT Inspect (Out of Scope)
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

            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
              <span className="text-[11px] text-slate-500">Point-in-time read-only inspection · Zero customer data modified</span>
              <button
                onClick={() => setCoverageModalOpen(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SCORE EXPLANATION MODAL ────────────────────────────────────── */}
      {scoreModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl animate-fade-in">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">How Your Security Score Is Calculated</h3>
                <p className="text-xs text-slate-400 mt-0.5">Transparent, deterministic scoring based on scan findings</p>
              </div>
              <button
                onClick={() => setScoreModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 transition-colors p-1 cursor-pointer bg-transparent border-none"
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-5 text-xs">
              {/* Formula Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Scoring Formula</p>
                <div className="font-mono text-xs sm:text-sm text-teal-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                  Score = max(0, 100 − [10 × Critical + 4 × Warnings + 1 × Orphaned])
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Scoring starts at 100 points. Points are subtracted per detected issue according to its severity level. The score is floored at 0.
                </p>
              </div>

              {/* Live Calculation */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Live Account Calculation</p>
                  <span className="text-xs font-mono font-bold text-slate-200">
                    Final Score: <span className="text-teal-400">{scoreData.score} / 100</span> ({scoreData.label})
                  </span>
                </div>

                <div className="divide-y divide-slate-800/80 font-mono text-[11px]">
                  <div className="py-1.5 flex justify-between">
                    <span className="text-slate-400">Base Starting Score:</span>
                    <span className="text-slate-200">+100 pts</span>
                  </div>
                  <div className="py-1.5 flex justify-between text-red-400">
                    <span>Critical Findings ({scoreData.critical} × −10 pts):</span>
                    <span>−{scoreData.critical * 10} pts</span>
                  </div>
                  <div className="py-1.5 flex justify-between text-amber-400">
                    <span>Warning Findings ({scoreData.warning} × −4 pts):</span>
                    <span>−{scoreData.warning * 4} pts</span>
                  </div>
                  <div className="py-1.5 flex justify-between text-slate-400">
                    <span>Orphaned Resources ({scoreData.orphaned} × −1 pt):</span>
                    <span>−{scoreData.orphaned * 1} pts</span>
                  </div>
                  <div className="py-2 flex justify-between font-bold text-xs border-t border-slate-700">
                    <span className="text-white font-sans">Calculated Score:</span>
                    <span className="text-teal-300">{scoreData.score} pts</span>
                  </div>
                </div>
              </div>

              {/* Supporting Counts */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Total Scanned</span>
                  <span className="text-base font-bold text-white font-mono">{scoreData.totalResources}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Healthy (0 Issues)</span>
                  <span className="text-base font-bold text-emerald-400 font-mono">{scoreData.healthy}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Need Attention</span>
                  <span className="text-base font-bold text-amber-400 font-mono">{scoreData.needsAttention}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Total Findings</span>
                  <span className="text-base font-bold text-slate-200 font-mono">{scoreData.totalFindings}</span>
                </div>
              </div>

              {/* Score Tiers */}
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <p className="font-semibold text-slate-300">Score Range Interpretations:</p>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-1 font-mono pt-1 text-center text-[10px]">
                  <span className="p-1 rounded bg-emerald-950/40 text-emerald-300 border border-emerald-500/20">90–100: Excellent</span>
                  <span className="p-1 rounded bg-teal-950/40 text-teal-300 border border-teal-500/20">75–89: Good</span>
                  <span className="p-1 rounded bg-amber-950/40 text-amber-300 border border-amber-500/20">50–74: Fair</span>
                  <span className="p-1 rounded bg-orange-950/40 text-orange-300 border border-orange-500/20">25–49: Poor</span>
                  <span className="p-1 rounded bg-red-950/40 text-red-300 border border-red-500/20">0–24: Critical</span>
                </div>
              </div>

              {/* Non-certification Disclaimer */}
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed">
                <p className="font-semibold text-slate-300 mb-0.5">Important Clarification</p>
                This score is an operational security posture indicator derived strictly from the checks performed above. It does not certify compliance with industry standards (e.g. SOC 2, ISO 27001, PCI-DSS, HIPAA, or CIS benchmarks) and does not guarantee that your AWS account is completely immune to security threats.
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
              <button
                onClick={() => setScoreModalOpen(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SECURITY CHECK CATALOG MODAL ──────────────────────────────── */}
      {catalogModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl animate-fade-in">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Security Check Catalog</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {SECURITY_CHECKS.length} security checks executed by AWS Clarity
                </p>
              </div>
              <button
                onClick={() => setCatalogModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 transition-colors p-1 cursor-pointer bg-transparent border-none"
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            {/* Filter bar */}
            <div className="px-5 pt-4 pb-3 border-b border-slate-800 space-y-3 bg-slate-950/40">
              <input
                type="text"
                value={catalogSearch}
                onChange={(e) => setCatalogSearch(e.target.value)}
                placeholder="Filter checks by name, rule ID, or service…"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500 transition-colors"
              />

              <div className="flex items-center gap-1.5 flex-wrap">
                {[
                  { key: "all",      label: "All Checks", count: checkCounts.total },
                  { key: "violated", label: "Violated",   count: checkCounts.violated, activeClass: "text-red-400 bg-red-500/10 border-red-500/20" },
                  { key: "passed",   label: "Passed",     count: checkCounts.passed,   activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
                  { key: "na",       label: "No Resources", count: checkCounts.na,     activeClass: "text-slate-400 bg-slate-500/10 border-slate-500/20" },
                ].map(tab => (
                  <button
                    key={tab.key}
                    onClick={() => setCatalogFilter(tab.key)}
                    className={`text-[11px] font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 border ${
                      catalogFilter === tab.key
                        ? (tab.activeClass || "text-teal-400 bg-teal-500/10 border-teal-500/20")
                        : "text-slate-400 hover:text-slate-200 border-transparent"
                    }`}
                  >
                    <span>{tab.label}</span>
                    <span className="text-[10px] font-mono tabular-nums px-1 rounded bg-slate-800">
                      {tab.count}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Checks list */}
            <div className="p-5 overflow-y-auto space-y-3 text-xs flex-1">
              {filteredChecks.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  No security checks match the current filter.
                </div>
              ) : (
                filteredChecks.map(check => {
                  const isViolated = check.eval.status === "VIOLATED";
                  const isPassed = check.eval.status === "PASSED";

                  return (
                    <div
                      key={check.id}
                      className={`p-3.5 rounded-xl border ${
                        isViolated
                          ? "border-red-500/30 bg-red-950/10"
                          : "border-slate-800 bg-slate-950/60"
                      } space-y-2`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap min-w-0">
                          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            {check.id}
                          </span>
                          <span className="font-semibold text-slate-100 text-xs">
                            {check.service} — {check.name}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="text-[10px] text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                            {check.service}
                          </span>
                          <span className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                            check.severity === "CRITICAL"
                              ? "text-red-400 bg-red-500/10"
                              : check.severity === "WARNING"
                              ? "text-amber-400 bg-amber-500/10"
                              : "text-slate-400 bg-slate-500/10"
                          }`}>
                            {check.severity}
                          </span>
                        </div>
                      </div>

                      <p className="text-slate-400 text-[11px] leading-relaxed">
                        {check.whatItChecks}
                      </p>

                      <div className="flex items-center justify-between pt-1 text-[11px] border-t border-slate-800/60">
                        <span className="text-slate-500">Live Status:</span>
                        <div className="flex items-center gap-1.5">
                          {isViolated && (
                            <span className="font-medium text-red-400 flex items-center gap-1">
                              <span>⚠ Violated</span>
                              <span className="font-mono text-[10px] text-red-300">
                                ({check.eval.label})
                              </span>
                            </span>
                          )}
                          {isPassed && (
                            <span className="font-medium text-emerald-400 flex items-center gap-1">
                              <span>✓ Passed</span>
                              <span className="font-mono text-[10px] text-emerald-500">
                                ({check.eval.label})
                              </span>
                            </span>
                          )}
                          {!isViolated && !isPassed && (
                            <span className="text-slate-500 font-mono text-[10px]">
                              — No resources scanned
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
              <span className="text-[11px] text-slate-500">
                Checks derived directly from scanner engine · Zero hypothetical checks
              </span>
              <button
                onClick={() => setCatalogModalOpen(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── DETAIL DRAWER ─────────────────────────────────────────────────── */}
      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          scannedAt={scannedAt || scanResults?.scanned_at}
          previousScannedAt={previousScanResults?.scanned_at}
          history={comparison.resourceHistoryMap?.get(getStableResourceId(selectedResource))}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
