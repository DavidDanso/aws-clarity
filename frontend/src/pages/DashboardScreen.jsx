import { useState, useMemo, useRef } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import ResourceTable from "../components/ResourceTable";
import TrustModal from "../components/TrustModal";
import CoverageModal from "../components/CoverageModal";
import ScoreModal from "../components/ScoreModal";
import ChecksCatalogModal from "../components/ChecksCatalogModal";
import {
  CATEGORY_BADGE,
  RESOURCE_COLLECTION_KEYS,
  RESOURCE_TYPE_LABELS,
  STATUS_COLOR,
} from "../utils/constants";
import { computeScore } from "../utils/securityScore";
import { compareScans, getStableResourceId } from "../utils/scanComparison";
import { scanAccount } from "../services/api";
import { SECURITY_CHECKS, evaluateCheckStatus } from "../utils/securityChecksCatalog";

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
          cx="40"
          cy="40"
          r={r}
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
        <span className={`text-4xl font-bold tabular-nums leading-none tracking-tight ${labelColor}`}>
          {score}
        </span>
        <span className={`text-sm font-semibold mt-1.5 leading-none ${labelColor}`}>{label}</span>
      </div>
    </div>
  );
}

function ChevronIcon({ open }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      className={`transition-transform duration-200 ${open ? "rotate-180" : ""}`}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

const SCAN_STAGE_LABELS = {
  STARTING: "Connecting to AWS via STS AssumeRole…",
  PENDING: "Queued read-only scan worker…",
  RUNNING: "Inspecting EC2, VPC, ELB, S3, RDS, DynamoDB, Lambda & IAM…",
};

export default function DashboardScreen({
  scanResults,
  previousScanResults,
  onRescan,
  onDisconnect,
  isLoading,
  scanStatus,
  scanError,
  storedRoleArn,
  storedExternalId,
  storedRegions,
  onStoredRegionsChange,
  onResultsChange,
}) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [coverageModalOpen, setCoverageModalOpen] = useState(false);
  const [scoreModalOpen, setScoreModalOpen] = useState(false);
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);
  const [comparisonExpanded, setComparisonExpanded] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved");
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanError, setRescanError] = useState(null);
  const [tableStatusFilter, setTableStatusFilter] = useState("ALL");

  const inventorySectionRef = useRef(null);

  const coverage = scanResults?.coverage || {};
  const permissionChecks = scanResults?.permission_checks || {};
  const scannerStatuses = coverage?.scanner_statuses || [];
  const completedScanners = scannerStatuses.filter((s) => s.status === "COMPLETED");
  const failedScanners = scannerStatuses.filter((s) => s.status !== "COMPLETED");

  const handleRegionChange = async (newRegions) => {
    if (!storedRoleArn || newRegions.length === 0) return;
    setIsRescanning(true);
    setRescanError(null);
    try {
      const newResults = await scanAccount(storedRoleArn, newRegions, undefined, storedExternalId);
      onResultsChange(newResults);
      onStoredRegionsChange(newRegions);
    } catch (err) {
      setRescanError(err.message || "Failed to switch regions. Please try again.");
    } finally {
      setIsRescanning(false);
    }
  };

  const jumpToInventory = (statusFilter) => {
    setTableStatusFilter(statusFilter);
    inventorySectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const previousAllResources = useMemo(() => {
    if (!previousScanResults?.resources) return [];
    return Object.values(previousScanResults.resources).flat().filter(Boolean);
  }, [previousScanResults]);

  const allResources = useMemo(() => {
    if (!scanResults?.resources) return [];
    return RESOURCE_COLLECTION_KEYS.flatMap((key) => scanResults.resources[key] || []);
  }, [scanResults]);

  const comparison = useMemo(
    () => compareScans(previousAllResources, allResources),
    [previousAllResources, allResources]
  );

  const scoreData = useMemo(() => computeScore(allResources), [allResources]);

  const activeCatalog = useMemo(() => {
    const rulesCatalog = scanResults?.coverage?.rules_catalog;
    if (Array.isArray(rulesCatalog) && rulesCatalog.length > 0) {
      return rulesCatalog;
    }
    return SECURITY_CHECKS;
  }, [scanResults]);

  const evaluatedChecks = useMemo(
    () =>
      activeCatalog.map((check) => ({
        ...check,
        eval: evaluateCheckStatus(check, allResources),
      })),
    [activeCatalog, allResources]
  );

  // Build prioritized "Needs Attention" list: top critical/warning security risks + top cost/unused risks
  const topAttentionItems = useMemo(() => {
    const items = [];
    const seen = new Set();

    const addMatching = (predicate, limit) => {
      let added = 0;
      for (const r of allResources) {
        for (const issue of r.issues || []) {
          if (!predicate(issue)) continue;
          const key = `${issue.rule_id || issue.title}::${r.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          items.push({ resource: r, issue });
          added++;
          if (added >= limit) return;
        }
      }
    };

    // 1. Up to 2 CRITICAL security issues
    addMatching((i) => i.severity === "CRITICAL", 2);
    // 2. Up to 2 Cost Risk / Unused (ORPHANED) items so billing risks are immediately visible
    addMatching((i) => i.category === "Cost Risk" || i.category === "Unused" || i.severity === "ORPHANED", 2);
    // 3. Fill remaining slots (up to 4 total) with WARNINGs if needed
    if (items.length < 4) {
      addMatching((i) => i.severity === "WARNING", 4 - items.length);
    }
    return items.slice(0, 4);
  }, [allResources]);

  // Comprehensive CSV export preserving exact status (including NOT_ASSESSED)
  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = [
      "Resource Name",
      "Resource ID",
      "Resource Type",
      "Region",
      "Status",
      "Category",
      "Rule ID",
      "Severity",
      "Finding",
      "Evidence",
      "Recommended Fix",
      "Issue Count",
    ];
    const rows = [];
    for (const r of allResources) {
      const issues = r.issues || [];
      const displayedStatus =
        r.status === "HEALTHY" && r.assessment?.status !== "ASSESSED"
          ? "NOT_ASSESSED"
          : r.status || "NOT_ASSESSED";

      if (issues.length === 0) {
        rows.push(
          [
            escape(r.name),
            escape(r.id),
            escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
            escape(r.region || ""),
            escape(displayedStatus),
            escape(""),
            escape(""),
            escape(displayedStatus),
            escape(displayedStatus === "HEALTHY" ? "No issues detected" : "Not fully assessed"),
            escape(""),
            escape(""),
            escape(0),
          ].join(",")
        );
      } else {
        for (const issue of issues) {
          const evidenceStr = issue.evidence
            ? Object.entries(issue.evidence)
                .map(([k, v]) => `${k}: ${v}`)
                .join(" | ")
            : "";
          rows.push(
            [
              escape(r.name),
              escape(r.id),
              escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
              escape(r.region || ""),
              escape(displayedStatus),
              escape(issue.category || ""),
              escape(issue.rule_id || ""),
              escape(issue.severity || ""),
              escape(issue.title || issue.message || ""),
              escape(evidenceStr),
              escape(issue.fix || ""),
              escape(issues.length),
            ].join(",")
          );
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

  const deltaLabel =
    comparison.scoreDelta > 0
      ? `+${comparison.scoreDelta} pts`
      : comparison.scoreDelta < 0
      ? `${comparison.scoreDelta} pts`
      : "no change";
  const deltaColor =
    comparison.scoreDelta > 0
      ? "text-emerald-400"
      : comparison.scoreDelta < 0
      ? "text-red-400"
      : "text-slate-500";

  const regionDisplay =
    scanResults?.regions?.length === 1
      ? scanResults.regions[0]
      : scanResults?.regions?.length > 1
      ? `${scanResults.regions.length} regions`
      : scanResults?.region || storedRegions?.[0] || "us-east-1";

  const servicesCount = coverage?.services_scanned?.length || completedScanners.length || 0;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="px-4 sm:px-6 lg:px-8 py-4 sm:py-6 max-w-5xl mx-auto w-full">
        <TopBar
          accountId={scanResults?.account_id || ""}
          scannedAt={scanResults?.scanned_at || ""}
          onRescan={onRescan}
          onDisconnect={onDisconnect}
          isLoading={isLoading}
          selectedRegions={storedRegions}
          onRegionChange={handleRegionChange}
          isRescanning={isRescanning}
          onOpenTrust={() => setTrustModalOpen(true)}
        />

        {isRescanning && (
          <div className="flex items-center gap-3 py-6 justify-center">
            <svg className="animate-spin w-5 h-5 text-teal-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <div className="text-left">
              <p className="text-sm font-medium text-slate-300">Scanning selected region…</p>
              <p className="text-xs text-slate-500 mt-0.5">Usually completes in 5–15 seconds.</p>
            </div>
          </div>
        )}

        {rescanError && (
          <div className="mt-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800/50 text-sm text-red-300 flex items-center justify-between gap-3">
            <span>{rescanError}</span>
            <button
              type="button"
              onClick={() => setRescanError(null)}
              className="shrink-0 text-red-400 hover:text-red-200 text-lg leading-none cursor-pointer bg-transparent border-none"
            >
              ×
            </button>
          </div>
        )}

        <main className={`mt-7 sm:mt-10 ${isRescanning ? "pointer-events-none opacity-40 select-none" : ""}`}>
          {/* Active Initial Scan State */}
          {isLoading && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-8 flex flex-col items-center text-center gap-4">
              <svg className="animate-spin w-8 h-8 text-teal-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
              <div>
                <p className="text-base font-semibold text-slate-100">
                  {SCAN_STAGE_LABELS[scanStatus] || "Running read-only AWS scan…"}
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Scanning {storedRegions?.join(", ")} · Strictly read-only · Temporary STS credentials
                </p>
              </div>
              <div className="w-full max-w-md space-y-2 pt-2">
                {[...Array(3)].map((_, i) => (
                  <div
                    key={i}
                    className="animate-pulse bg-slate-800/70 h-8 rounded-lg"
                    style={{ opacity: 1 - i * 0.2 }}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Scan Error State */}
          {!isLoading && scanError && (
            <div className="rounded-2xl border border-red-800/50 bg-red-950/20 p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="space-y-1">
                <p className="text-sm font-semibold text-red-300">Unable to complete scan</p>
                <p className="text-xs text-red-200/80 leading-relaxed">{scanError}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={onDisconnect}
                  className="px-3 py-1.5 text-xs rounded-lg border border-slate-700 text-slate-300 hover:text-white cursor-pointer bg-transparent"
                >
                  Edit Role ARN
                </button>
                <button
                  type="button"
                  onClick={onRescan}
                  className="px-3 py-1.5 text-xs rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-semibold cursor-pointer"
                >
                  Retry Scan
                </button>
              </div>
            </div>
          )}

          {/* Empty Account State */}
          {!isLoading && !scanError && scanResults && allResources.length === 0 && (
            <div className="flex flex-col items-center justify-center gap-4 py-20 text-center px-4 rounded-2xl border border-slate-800 bg-slate-900/30">
              <svg xmlns="http://www.w3.org/2000/svg" width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-slate-600">
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <div>
                <p className="text-base font-medium text-slate-300">No resources found in {regionDisplay}</p>
                <p className="text-xs text-slate-500 mt-1 max-w-sm">
                  No resources were discovered across the 14 supported resource types in this region. Try switching regions in the top bar or review scan coverage.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setCoverageModalOpen(true)}
                className="text-xs text-teal-400 hover:text-teal-300 underline cursor-pointer bg-transparent border-none"
              >
                View scan coverage & permissions →
              </button>
            </div>
          )}

          {/* Main Dashboard: 3-Level Progressive Flow */}
          {!isLoading && !scanError && scanResults && allResources.length > 0 && (
            <div className="flex flex-col space-y-10 sm:space-y-12">
              {/* Scan Reliability Context Banner */}
              <div
                className={`p-3 sm:p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 text-xs ${
                  failedScanners.length > 0 || scanResults.partial
                    ? "bg-amber-950/20 border-amber-500/30 text-amber-200"
                    : "bg-slate-900/50 border-slate-800 text-slate-300"
                }`}
              >
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      failedScanners.length > 0 || scanResults.partial ? "bg-amber-400" : "bg-teal-400"
                    }`}
                  />
                  <span className="font-semibold text-slate-100">
                    {failedScanners.length > 0
                      ? `Partial scan (${failedScanners.length} scanner issue${failedScanners.length === 1 ? "" : "s"})`
                      : scanResults.partial
                      ? "Scan complete (some checks unassessed)"
                      : "Scan complete"}
                  </span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">{allResources.length} resources</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">{servicesCount} services</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">{regionDisplay}</span>
                </div>

                <button
                  type="button"
                  onClick={() => setCoverageModalOpen(true)}
                  className="text-[11px] font-semibold text-slate-400 hover:text-slate-200 underline underline-offset-2 transition-colors cursor-pointer bg-transparent border-none p-0 self-start sm:self-auto shrink-0"
                >
                  {failedScanners.length > 0 || scanResults.partial
                    ? "View partial errors & scope →"
                    : "View coverage breakdown →"}
                </button>
              </div>

              {/* LEVEL 1 — ACCOUNT HEALTH & COST POSTURE */}
              <section className="space-y-4">
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                  Account Health & Cost Posture
                </p>

                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
                  <ScoreRing
                    score={scoreData.score}
                    label={scoreData.label}
                    labelColor={scoreData.labelColor}
                  />

                  <div className="flex flex-wrap items-center gap-2.5 text-xs">
                    <button
                      type="button"
                      onClick={() => jumpToInventory("CRITICAL")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors cursor-pointer font-medium"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                      <span>{scoreData.critical} Critical</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => jumpToInventory("WARNING")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20 transition-colors cursor-pointer font-medium"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                      <span>{scoreData.warning} Warning{scoreData.warning === 1 ? "" : "s"}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => jumpToInventory("COST_UNUSED")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-300 hover:bg-sky-500/20 transition-colors cursor-pointer font-medium"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                      <span>{scoreData.costAndUnusedFindings} Cost / Unused</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => jumpToInventory("HEALTHY")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors cursor-pointer font-medium"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      <span>{scoreData.healthy} Healthy</span>
                    </button>
                    {scoreData.notAssessed > 0 && (
                      <button
                        type="button"
                        onClick={() => jumpToInventory("NOT_ASSESSED")}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer font-medium"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                        <span>{scoreData.notAssessed} Unassessed</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Supporting Transparency Links + Scan Comparison */}
                <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap pt-1">
                  <button
                    type="button"
                    onClick={() => setScoreModalOpen(true)}
                    className="hover:text-slate-200 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                  >
                    How score is calculated
                  </button>
                  <span>·</span>
                  <button
                    type="button"
                    onClick={() => setCatalogModalOpen(true)}
                    className="hover:text-slate-200 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                  >
                    Checks catalog ({activeCatalog.length} rules)
                  </button>
                  <span>·</span>
                  <button
                    type="button"
                    onClick={() => setCoverageModalOpen(true)}
                    className="hover:text-slate-200 transition-colors cursor-pointer bg-transparent border-none p-0 text-slate-400"
                  >
                    Coverage & scope
                  </button>

                  {comparison.hasPrevious && (
                    <>
                      <span>·</span>
                      <span className="text-slate-400">
                        Previous: {comparison.previousScore} → {comparison.currentScore}
                      </span>
                      <span className={`font-semibold ${deltaColor}`}>{deltaLabel}</span>
                      <button
                        type="button"
                        onClick={() => setComparisonExpanded((prev) => !prev)}
                        className="hover:text-slate-200 flex items-center gap-1 cursor-pointer bg-transparent border-none p-0 text-slate-400"
                      >
                        Diff <ChevronIcon open={comparisonExpanded} />
                      </button>
                    </>
                  )}
                </div>

                {/* Expandable Scan Comparison Panel */}
                {comparisonExpanded && comparison.hasPrevious && (
                  <div className="border border-slate-800/80 rounded-xl p-4 flex flex-col gap-3 bg-slate-900/40">
                    <div className="flex items-center gap-1 flex-wrap">
                      {[
                        { key: "resolved", label: "✓ Resolved", count: comparison.resolvedCount, activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
                        { key: "stillOpen", label: "⚠ Still Open", count: comparison.stillOpenCount, activeClass: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
                        { key: "new", label: "⚡ New Issues", count: comparison.newCount, activeClass: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" },
                        { key: "newResources", label: "New Resources", count: comparison.newResourcesCount, activeClass: "text-sky-400 bg-sky-500/10 border-sky-500/20" },
                        { key: "removedResources", label: "Removed", count: comparison.removedResourcesCount, activeClass: "text-rose-400 bg-rose-500/10 border-rose-500/20" },
                        { key: "statusChanges", label: "Status Changes", count: comparison.statusChangesCount, activeClass: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20" },
                      ].map((tab) => (
                        <button
                          type="button"
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
                      {progressTab === "resolved" &&
                        (comparison.resolvedCount === 0 ? (
                          <p className="text-slate-500 py-1">No findings resolved since the previous scan.</p>
                        ) : (
                          comparison.resolved.map((item, idx) => (
                            <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-emerald-950/20">
                              <span className="text-emerald-400 font-bold shrink-0">✓</span>
                              {item.ruleId && <span className="text-[10px] font-mono text-emerald-400 shrink-0">{item.ruleId}</span>}
                              <span className="text-slate-300 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                            </div>
                          ))
                        ))}
                      {progressTab === "stillOpen" &&
                        (comparison.stillOpenCount === 0 ? (
                          <p className="text-slate-500 py-1">No findings carried over.</p>
                        ) : (
                          comparison.stillOpen.map((item, idx) => (
                            <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-amber-950/20">
                              <span className="text-amber-400 font-bold shrink-0">⚠</span>
                              {item.ruleId && <span className="text-[10px] font-mono text-amber-400 shrink-0">{item.ruleId}</span>}
                              <span className="text-slate-300 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                            </div>
                          ))
                        ))}
                      {progressTab === "new" &&
                        (comparison.newCount === 0 ? (
                          <p className="text-slate-500 py-1">No new findings discovered.</p>
                        ) : (
                          comparison.newFindings.map((item, idx) => (
                            <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-cyan-950/20">
                              <span className="text-cyan-400 font-bold shrink-0">⚡</span>
                              {item.ruleId && <span className="text-[10px] font-mono text-cyan-400 shrink-0">{item.ruleId}</span>}
                              <span className="text-slate-300 truncate">{item.title}</span>
                              <span className="text-slate-500 text-[11px] truncate shrink-0">({item.resourceName})</span>
                            </div>
                          ))
                        ))}
                      {progressTab === "newResources" &&
                        (comparison.newResourcesCount === 0 ? (
                          <p className="text-slate-500 py-1">No new resources discovered.</p>
                        ) : (
                          comparison.newResources.map((item, idx) => (
                            <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-sky-950/20">
                              <span className="text-slate-300 truncate">
                                <span className="text-[10px] font-mono text-sky-400 mr-2 uppercase">{item.type}</span>
                                {item.name || item.id}
                              </span>
                              <span className={`text-[10px] font-semibold uppercase ${STATUS_COLOR[item.status] || "text-slate-400"}`}>
                                {item.status}
                              </span>
                            </div>
                          ))
                        ))}
                      {progressTab === "removedResources" &&
                        (comparison.removedResourcesCount === 0 ? (
                          <p className="text-slate-500 py-1">No resources removed.</p>
                        ) : (
                          comparison.removedResources.map((item, idx) => (
                            <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-rose-950/20">
                              <span className="text-slate-300 truncate">
                                <span className="text-[10px] font-mono text-rose-400 mr-2 uppercase">{item.type}</span>
                                {item.name || item.id}
                              </span>
                              <span className="text-[10px] text-slate-500 font-mono">Removed</span>
                            </div>
                          ))
                        ))}
                      {progressTab === "statusChanges" &&
                        (comparison.statusChangesCount === 0 ? (
                          <p className="text-slate-500 py-1">No resource status changes.</p>
                        ) : (
                          comparison.statusChanges.map((item, idx) => (
                            <div key={idx} className="flex items-center justify-between py-1 px-2 rounded bg-indigo-950/20">
                              <span className="text-slate-300 truncate">{item.resourceName}</span>
                              <div className="flex items-center gap-1.5 shrink-0 text-[11px] font-mono">
                                <span className={STATUS_COLOR[item.previousStatus] || "text-slate-400"}>{item.previousStatus}</span>
                                <span className="text-slate-500">→</span>
                                <span className={STATUS_COLOR[item.currentStatus] || "text-slate-400"}>{item.currentStatus}</span>
                              </div>
                            </div>
                          ))
                        ))}
                    </div>
                  </div>
                )}
              </section>

              {/* LEVEL 2 — NEEDS ATTENTION (SECURITY & COST RISKS) */}
              <section>
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-3">
                  Needs Attention — Top Security & Cost Risks
                </p>

                {topAttentionItems.length > 0 ? (
                  <div className="divide-y divide-slate-800/60 border-y border-slate-800/60">
                    {topAttentionItems.map(({ resource, issue }, idx) => (
                      <div
                        key={`${issue.rule_id}-${resource.id}-${idx}`}
                        className="py-3.5 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3"
                      >
                        <div className="flex flex-col gap-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`text-[11px] font-semibold uppercase tracking-wider ${
                                issue.severity === "CRITICAL"
                                  ? "text-red-400"
                                  : issue.severity === "WARNING"
                                  ? "text-amber-400"
                                  : "text-sky-300"
                              }`}
                            >
                              {issue.severity}
                            </span>
                            {issue.category && (
                              <span
                                className={`text-[10px] px-1.5 py-0.5 rounded border ${
                                  CATEGORY_BADGE[issue.category] || "bg-slate-800 text-slate-400 border-slate-700"
                                }`}
                              >
                                {issue.category}
                              </span>
                            )}
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
                          type="button"
                          onClick={() => setSelectedResource(resource)}
                          className="text-xs text-teal-400 hover:text-teal-300 font-medium bg-transparent border-none p-0 cursor-pointer shrink-0 sm:pt-0.5 self-start whitespace-nowrap transition-colors"
                        >
                          Inspect & Fix →
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5 py-3 px-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 text-emerald-300 text-[13px]">
                    <svg className="w-4 h-4 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    <span>No critical security issues or unused cost risks detected across checked resources.</span>
                  </div>
                )}
              </section>

              {/* LEVEL 3 — CENTRAL RESOURCE INVENTORY */}
              <section ref={inventorySectionRef} className="scroll-mt-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                      Resource Inventory
                    </p>
                    <p className="text-[12px] text-slate-500 mt-0.5">
                      {allResources.length} resources across {servicesCount} AWS services · {regionDisplay}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleExportCSV}
                    className="text-xs px-3 py-1.5 rounded-lg border border-slate-800 hover:border-slate-600 text-slate-300 hover:text-white cursor-pointer bg-slate-900/60 transition-colors"
                  >
                    Export CSV
                  </button>
                </div>

                <ResourceTable
                  resources={allResources}
                  initialStatusFilter={tableStatusFilter}
                  onInspect={(resource) => setSelectedResource(resource)}
                />
              </section>
            </div>
          )}
        </main>
      </div>

      {/* Modals & Drawer */}
      <CoverageModal
        isOpen={coverageModalOpen}
        onClose={() => setCoverageModalOpen(false)}
        coverage={coverage}
        permissionChecks={permissionChecks}
        scannerStatuses={scannerStatuses}
        completedScanners={completedScanners}
        failedScanners={failedScanners}
        servicesCount={servicesCount}
        allResourcesCount={allResources.length}
        regionDisplay={regionDisplay}
      />

      <ScoreModal
        isOpen={scoreModalOpen}
        onClose={() => setScoreModalOpen(false)}
        scoreData={scoreData}
      />

      <ChecksCatalogModal
        isOpen={catalogModalOpen}
        onClose={() => setCatalogModalOpen(false)}
        evaluatedChecks={evaluatedChecks}
      />

      <TrustModal isOpen={trustModalOpen} onClose={() => setTrustModalOpen(false)} />

      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          scannedAt={scanResults?.scanned_at}
          previousScannedAt={previousScanResults?.scanned_at}
          history={comparison.resourceHistoryMap?.get(getStableResourceId(selectedResource))}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
