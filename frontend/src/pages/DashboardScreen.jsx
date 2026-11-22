import { useState, useMemo, useRef, useEffect } from "react";
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
  STARTING: "Verifying AWS identity via STS AssumeRole…",
  PENDING: "Starting parallel read-only scan worker…",
  DISCOVERING: "Discovering enabled AWS regions & global services…",
  SCANNING: "Scanning all 10 AWS services across enabled regions…",
  EVALUATING: "Running deterministic security & cost rules…",
  RUNNING: "Discovering enabled regions & scanning all 10 AWS services…",
};

export default function DashboardScreen({
  scanResults,
  previousScanResults,
  isDemoMode = false,
  onExitDemo,
  onRescan,
  onDisconnect,
  isLoading,
  scanStatus,
  scanProgress,
  scanError,
  dataControls = null,
}) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [coverageModalOpen, setCoverageModalOpen] = useState(false);
  const [scoreModalOpen, setScoreModalOpen] = useState(false);
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);
  const [comparisonExpanded, setComparisonExpanded] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved");
  const [tableStatusFilter, setTableStatusFilter] = useState("ALL");
  const [tableCategoryFilter, setTableCategoryFilter] = useState("ALL");
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    if (!isLoading) return undefined;
    const startedAt = Date.now();
    const timer = setInterval(() => {
      setElapsedMs(Date.now() - startedAt);
    }, 100);
    return () => {
      clearInterval(timer);
      setElapsedMs(0);
    };
  }, [isLoading]);

  const progressRegionsTotal = scanProgress?.regions_total || 0;
  const progressRegionsDone = scanProgress?.regions_done || 0;
  const progressResourcesFound = scanProgress?.resources_found || 0;
  const progressStage = scanProgress?.stage || scanStatus;
  const smoothElapsedPct = Math.min(88, Math.round(14 + (1 - Math.exp(-elapsedMs / 2200)) * 74));
  const progressPct =
    progressStage === "EVALUATING"
      ? 96
      : progressRegionsTotal > 0
      ? Math.min(92, Math.max(12, Math.round((progressRegionsDone / progressRegionsTotal) * 90)))
      : smoothElapsedPct;

  const inventorySectionRef = useRef(null);

  const coverage = scanResults?.coverage || {};
  const coverageFailures = coverage?.failures || [];
  const isIncompleteScan =
    coverage?.status === "INCOMPLETE" ||
    scanResults?.partial === true ||
    coverageFailures.length > 0;
  const regionsScanned = coverage?.regions_scanned || scanResults?.regions || [];
  const accountAdvisories = scanResults?.account_advisories || [];

  const jumpToInventory = (statusFilter, categoryFilter = "ALL") => {
    setTableStatusFilter(statusFilter);
    setTableCategoryFilter(categoryFilter);
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

  const scoreData = useMemo(
    () => computeScore(allResources, isIncompleteScan),
    [allResources, isIncompleteScan]
  );

  const previousScanIncomplete =
    previousScanResults?.coverage?.status === "INCOMPLETE" ||
    previousScanResults?.partial === true ||
    (previousScanResults?.coverage?.failures || []).length > 0;

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

  // Prioritized "Needs Attention" list: critical security risks + top cost/unused items
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

    addMatching((i) => i.severity === "CRITICAL", 2);
    addMatching(
      (i) =>
        i.severity !== "INFO" &&
        (i.category === "Potential Cost Waste" ||
          i.category === "Cost Risk" ||
          i.category === "Unused" ||
          i.severity === "UNUSED"),
      2
    );
    if (items.length < 4) {
      addMatching((i) => i.severity === "WARNING", 4 - items.length);
    }
    return items.slice(0, 4);
  }, [allResources]);

  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = [
      "Service",
      "Resource Name",
      "Resource ID",
      "Resource Type",
      "Region",
      "Health Status",
      "Category",
      "Rule ID",
      "Severity",
      "Finding",
      "Evidence",
      "Recommended Fix",
      "How to Verify",
    ];
    const rows = [];
    for (const r of allResources) {
      const issues = r.issues || [];
      const displayedStatus =
        r.status === "HEALTHY" && r.assessment?.status !== "COMPLETE"
          ? "INCOMPLETE"
          : r.status || "INCOMPLETE";

      if (issues.length === 0) {
        rows.push(
          [
            escape(r.service || ""),
            escape(r.name),
            escape(r.id),
            escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
            escape(r.region || "global"),
            escape(displayedStatus),
            escape(""),
            escape(""),
            escape(displayedStatus),
            escape(displayedStatus === "HEALTHY" ? "All applicable checks passed" : "Check blocked by API/IAM error"),
            escape(""),
            escape(""),
            escape(""),
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
              escape(r.service || ""),
              escape(r.name),
              escape(r.id),
              escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
              escape(r.region || "global"),
              escape(displayedStatus),
              escape(issue.category || ""),
              escape(issue.rule_id || ""),
              escape(issue.severity || ""),
              escape(issue.title || issue.message || ""),
              escape(evidenceStr),
              escape(issue.fix || ""),
              escape(issue.verify || ""),
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

  return (
    <div className="min-h-[100dvh] bg-slate-950 text-white">
      <div className="px-3.5 sm:px-6 lg:px-8 py-4 sm:py-6 pb-20 sm:pb-16 max-w-7xl mx-auto w-full">
        <TopBar
          accountId={scanResults?.account_id || ""}
          regionsCount={regionsScanned.length}
          scannedAt={scanResults?.scanned_at || ""}
          isDemoMode={isDemoMode}
          onExitDemo={onExitDemo}
          onRescan={onRescan}
          onDisconnect={onDisconnect}
          isLoading={isLoading}
          onOpenTrust={() => setTrustModalOpen(true)}
        />

        <main className="mt-6 sm:mt-9">
          {/* Unmistakable Demonstration Mode Banner */}
          {isDemoMode && (
            <div className="mb-6 rounded-xl border border-indigo-500/40 bg-indigo-950/30 p-3.5 sm:p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs">
              <div className="space-y-0.5 min-w-0">
                <p className="font-semibold text-indigo-200">
                  Demonstration Account — Sample AWS Assessment Data Only
                </p>
                <p className="text-indigo-200/80 text-[11px] leading-relaxed">
                  You are viewing static fixture data covering CRITICAL, WARNING, UNUSED, INFO, HEALTHY, and INCOMPLETE
                  states across all 10 supported services. Demo data is never stored or mixed with real AWS scans.
                </p>
              </div>
              <button
                type="button"
                onClick={onExitDemo}
                className="self-start sm:self-auto shrink-0 px-3.5 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold cursor-pointer transition-colors"
              >
                Connect Your AWS Account →
              </button>
            </div>
          )}
          {/* Active Scan Progress */}
          {isLoading && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 sm:p-8 flex flex-col items-center text-center gap-5">
              <div className="flex flex-wrap items-center justify-center gap-2.5 sm:gap-3">
                <svg className="animate-spin w-6 h-6 text-teal-400 shrink-0" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                <p className="text-sm sm:text-base font-semibold text-slate-100">
                  {SCAN_STAGE_LABELS[progressStage] || "Running parallel multi-region read-only AWS scan…"}
                </p>
              </div>

              <div className="w-full max-w-md space-y-2.5">
                <div
                  role="progressbar"
                  aria-label="AWS account scan progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progressPct}
                  className="w-full h-2 rounded-full bg-slate-800 overflow-hidden"
                >
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-teal-500 to-emerald-400 transition-[width] duration-300 ease-out"
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-[11px] sm:text-xs font-mono text-slate-400 tabular-nums">
                  <span className="text-left">
                    {progressRegionsTotal > 0
                      ? `${progressRegionsDone} / ${progressRegionsTotal} regions · ${progressResourcesFound} resources`
                      : "Parallel multi-region scan across all enabled AWS regions…"}
                  </span>
                  <span className="text-teal-400 shrink-0">{(elapsedMs / 1000).toFixed(1)}s</span>
                </div>
              </div>

              <p className="text-[11px] sm:text-xs text-slate-500 leading-relaxed">
                EC2 · VPC · S3 · IAM · Lambda · RDS · DynamoDB · EBS · CloudWatch · CloudTrail
              </p>
            </div>
          )}

          {/* Scan Failed State */}
          {!isLoading && scanError && (
            <div className="rounded-2xl border border-red-800/50 bg-red-950/20 p-4 sm:p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="space-y-1 min-w-0">
                <p className="text-sm font-semibold text-red-300">Unable to complete account scan</p>
                <p className="text-xs text-red-200/80 leading-relaxed break-words">{scanError}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={onDisconnect}
                  className="flex-1 sm:flex-none px-3 py-2 sm:py-1.5 text-xs rounded-lg border border-slate-700 text-slate-300 hover:text-white cursor-pointer bg-transparent text-center"
                >
                  Back to Connection Setup
                </button>
                <button
                  type="button"
                  onClick={onRescan}
                  className="flex-1 sm:flex-none px-3 py-2 sm:py-1.5 text-xs rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-semibold cursor-pointer text-center"
                >
                  Retry Scan
                </button>
              </div>
            </div>
          )}

          {/* Connected Account Dashboard */}
          {!isLoading && !scanError && scanResults && (
            <div className="flex flex-col space-y-8 sm:space-y-11">
              {/* SEPARATE INVENTORY COVERAGE STATUS BANNER */}
              <div
                className={`p-3.5 rounded-xl border flex flex-col md:flex-row md:items-center md:justify-between gap-2.5 text-xs ${
                  isIncompleteScan
                    ? "bg-orange-950/25 border-orange-500/40 text-orange-200"
                    : "bg-slate-900/50 border-slate-800 text-slate-300"
                }`}
              >
                <div className="flex items-center gap-x-2 gap-y-1 flex-wrap min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      isIncompleteScan ? "bg-orange-400" : "bg-emerald-400"
                    }`}
                  />
                  <span className="font-semibold text-slate-100">
                    {isIncompleteScan
                      ? `Incomplete Scan Coverage (${coverageFailures.length} failure${coverageFailures.length === 1 ? "" : "s"} reported)`
                      : "Complete Scan Coverage"}
                  </span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">{allResources.length} resources discovered</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">10 services</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">
                    {regionsScanned.length} enabled region{regionsScanned.length === 1 ? "" : "s"}
                  </span>
                  {typeof scanResults?.scan_duration_ms === "number" && (
                    <>
                      <span className="text-slate-600">·</span>
                      <span className="font-mono text-teal-400">
                        {(scanResults.scan_duration_ms / 1000).toFixed(1)}s
                      </span>
                    </>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => setCoverageModalOpen(true)}
                  className={`text-[11px] font-semibold underline underline-offset-2 transition-colors cursor-pointer bg-transparent border-none p-0 self-start md:self-auto shrink-0 ${
                    isIncompleteScan ? "text-orange-300 hover:text-orange-200" : "text-teal-400 hover:text-teal-300"
                  }`}
                >
                  {isIncompleteScan ? "Inspect affected services & regions →" : "View 10-service coverage matrix →"}
                </button>
              </div>

              {/* Account-Level Advisories (e.g. No CloudTrail trails in account) */}
              {accountAdvisories.length > 0 && (
                <div className="space-y-2.5">
                  {accountAdvisories.map((adv, idx) => (
                    <div
                      key={`${adv.rule_id}-${idx}`}
                      className="rounded-xl border border-red-500/35 bg-red-950/20 p-3.5 sm:p-4 text-xs space-y-1.5 break-words"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
                          {adv.rule_id}
                        </span>
                        <span className="text-[11px] font-bold uppercase text-red-400">{adv.severity}</span>
                        <span className="text-sm font-semibold text-red-100">{adv.title}</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed">{adv.why}</p>
                      <p className="text-teal-300 leading-relaxed"><strong className="text-teal-400">Fix:</strong> {adv.fix}</p>
                      <p className="text-emerald-300/90 leading-relaxed"><strong className="text-emerald-400">Verify:</strong> {adv.verify}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* LEVEL 1 — SECURITY, OPERATIONAL & COST ASSESSMENT RESULTS */}
              <section className="space-y-4">
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                  Assessment Summary — Security Risks · Operational Concerns · Potential Cost Waste
                </p>

                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
                  {scoreData.isAvailable ? (
                    <ScoreRing
                      score={scoreData.score}
                      label={scoreData.label}
                      labelColor={scoreData.labelColor}
                    />
                  ) : (
                    <div className="rounded-xl border border-orange-500/35 bg-orange-950/20 px-4 py-3.5 max-w-md space-y-1.5">
                      <p className="text-sm font-semibold text-orange-200">
                        Health score unavailable — assessment incomplete.
                      </p>
                      <p className="text-xs text-orange-200/80 leading-relaxed">
                        {coverageFailures.length > 0
                          ? `${coverageFailures.length} collection or check failure${coverageFailures.length === 1 ? "" : "s"} prevented a complete account assessment.`
                          : "One or more resource checks could not complete."}{" "}
                        AWS Clarity withholds the numeric score so partial scans are never mistaken for a 100/100 healthy account.
                      </p>
                      <button
                        type="button"
                        onClick={() => setCoverageModalOpen(true)}
                        className="text-xs font-semibold text-orange-300 hover:text-orange-200 underline underline-offset-2 cursor-pointer bg-transparent border-none p-0"
                      >
                        Inspect incomplete services &amp; regions →
                      </button>
                    </div>
                  )}

                  <div className="space-y-2.5 w-full md:w-auto">
                    {/* 3 Finding Category Buttons */}
                    <div className="grid grid-cols-1 sm:flex sm:flex-wrap items-center gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() => jumpToInventory("ALL", "Security Risk")}
                        className="flex items-center justify-between sm:justify-start gap-2 px-3 py-2 sm:py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/25 text-rose-300 hover:bg-rose-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span>Security Risks</span>
                        <span className="font-mono font-bold">{scoreData.securityRisks}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => jumpToInventory("ALL", "Operational Concern")}
                        className="flex items-center justify-between sm:justify-start gap-2 px-3 py-2 sm:py-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-indigo-300 hover:bg-indigo-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span>Operational Concerns</span>
                        <span className="font-mono font-bold">{scoreData.operationalConcerns}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => jumpToInventory("ALL", "Potential Cost Waste")}
                        className="flex items-center justify-between sm:justify-start gap-2 px-3 py-2 sm:py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-amber-300 hover:bg-amber-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span>Potential Cost Waste</span>
                        <span className="font-mono font-bold">{scoreData.potentialCostWaste}</span>
                      </button>
                    </div>

                    {/* Severity Quick Filters */}
                    <div className="grid grid-cols-2 sm:flex sm:flex-wrap items-center gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() => jumpToInventory("CRITICAL", "ALL")}
                        className="flex items-center justify-center sm:justify-start gap-1.5 px-2.5 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                        <span>{scoreData.critical} Critical</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => jumpToInventory("WARNING", "ALL")}
                        className="flex items-center justify-center sm:justify-start gap-1.5 px-2.5 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
                        <span>{scoreData.warning} Warning{scoreData.warning === 1 ? "" : "s"}</span>
                      </button>
                      {scoreData.info > 0 && (
                        <button
                          type="button"
                          onClick={() => jumpToInventory("INFO", "ALL")}
                          className="flex items-center justify-center sm:justify-start gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-500/10 border border-slate-600/40 text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer font-medium"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                          <span>{scoreData.info} Review Info</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => jumpToInventory("HEALTHY", "ALL")}
                        className="flex items-center justify-center sm:justify-start gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors cursor-pointer font-medium"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                        <span>{scoreData.healthy} Healthy</span>
                      </button>
                      {scoreData.incomplete > 0 && (
                        <button
                          type="button"
                          onClick={() => jumpToInventory("INCOMPLETE", "ALL")}
                          className="col-span-2 sm:col-span-1 flex items-center justify-center sm:justify-start gap-1.5 px-2.5 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/25 text-orange-300 hover:bg-orange-500/20 transition-colors cursor-pointer font-medium"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" />
                          <span>{scoreData.incomplete} Incomplete</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Transparency Links & Scan Verification Diff */}
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
                    Coverage report
                  </button>

                  {comparison.hasPrevious && (
                    <>
                      <span>·</span>
                      {scoreData.isAvailable && !previousScanIncomplete ? (
                        <>
                          <span className="text-slate-400">
                            Previous: {comparison.previousScore} → {comparison.currentScore}
                          </span>
                          <span className={`font-semibold ${deltaColor}`}>{deltaLabel}</span>
                        </>
                      ) : (
                        <span className="text-slate-400">
                          Scan Diff: {comparison.newCount} new · {comparison.resolvedCount} resolved · {comparison.stillOpenCount} unchanged
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => setComparisonExpanded((prev) => !prev)}
                        className="hover:text-slate-200 flex items-center gap-1 cursor-pointer bg-transparent border-none p-0 text-teal-400"
                      >
                        Scan Diff <ChevronIcon open={comparisonExpanded} />
                      </button>
                    </>
                  )}
                </div>

                {comparisonExpanded && comparison.hasPrevious && (
                  <div className="border border-slate-800/80 rounded-xl p-4 flex flex-col gap-3 bg-slate-900/40">
                    <div className="flex items-center gap-1 flex-wrap">
                      {[
                        { key: "new", label: "⚡ New", count: comparison.newCount, activeClass: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" },
                        { key: "resolved", label: "✓ Resolved", count: comparison.resolvedCount, activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
                        { key: "stillOpen", label: "• Unchanged", count: comparison.stillOpenCount, activeClass: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
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

              {/* LEVEL 2 — NEEDS ATTENTION */}
              <section>
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-3">
                  Needs Attention — Top Security &amp; Cost Risks
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
                            {RESOURCE_TYPE_LABELS[resource.type] || resource.type} · {resource.name} ·{" "}
                            <span className="font-mono">{resource.region || "global"}</span>
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
                          Inspect &amp; Fix →
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5 py-3 px-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 text-emerald-300 text-[13px]">
                    <svg className="w-4 h-4 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    <span>
                      {isIncompleteScan
                        ? "No findings detected in completed checks, though scan coverage is incomplete (inspect coverage above)."
                        : "No security issues or unused cost risks detected across your connected account."}
                    </span>
                  </div>
                )}
              </section>

              {/* LEVEL 3 — CENTRAL RESOURCE INVENTORY */}
              <section ref={inventorySectionRef} className="scroll-mt-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
                  <div className="min-w-0">
                    <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                      Complete Account Inventory (10 Supported Services)
                    </p>
                    <p className="text-[12px] text-slate-500 mt-0.5">
                      {allResources.length} actual resources discovered across {regionsScanned.length} enabled region{regionsScanned.length === 1 ? "" : "s"}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleExportCSV}
                    disabled={allResources.length === 0}
                    className="self-start sm:self-auto text-xs px-3 py-2 sm:py-1.5 rounded-lg border border-slate-800 hover:border-slate-600 text-slate-300 hover:text-white cursor-pointer bg-slate-900/60 transition-colors disabled:opacity-40 shrink-0"
                  >
                    Export CSV
                  </button>
                </div>

                <ResourceTable
                  resources={allResources}
                  initialStatusFilter={tableStatusFilter}
                  initialCategoryFilter={tableCategoryFilter}
                  onInspect={(resource) => setSelectedResource(resource)}
                />
              </section>
            </div>
          )}
        </main>
      </div>

      <CoverageModal
        isOpen={coverageModalOpen}
        onClose={() => setCoverageModalOpen(false)}
        coverage={coverage}
        allResourcesCount={allResources.length}
      />

      <ScoreModal
        isOpen={scoreModalOpen}
        onClose={() => setScoreModalOpen(false)}
        scoreData={scoreData}
        coverageFailuresCount={coverageFailures.length}
      />

      <ChecksCatalogModal
        isOpen={catalogModalOpen}
        onClose={() => setCatalogModalOpen(false)}
        evaluatedChecks={evaluatedChecks}
      />

      <TrustModal
        isOpen={trustModalOpen}
        onClose={() => setTrustModalOpen(false)}
        dataControls={dataControls}
      />

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
