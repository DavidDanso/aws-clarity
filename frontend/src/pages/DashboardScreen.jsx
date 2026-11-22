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
import { SECURITY_CHECKS, evaluateCheckStatus } from "../utils/securityChecksCatalog";
import { parseLocalAssessmentReport } from "../utils/reportImporter";
import {
  buildInventoryCSV,
  downloadLocalFile,
  sanitizeReportForSharing,
} from "../utils/reportSanitizer";

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

export default function DashboardScreen({
  scanResults,
  previousScanResults,
  importedFileName = "",
  isDemoMode = false,
  onExitDemo,
  onImportNewerReport,
  onReturnHome,
  dataControls = null,
}) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [coverageModalOpen, setCoverageModalOpen] = useState(false);
  const [scoreModalOpen, setScoreModalOpen] = useState(false);
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [diffImportError, setDiffImportError] = useState("");
  const [comparisonExpanded, setComparisonExpanded] = useState(false);
  const [progressTab, setProgressTab] = useState("resolved");
  const [tableStatusFilter, setTableStatusFilter] = useState("ALL");
  const [tableCategoryFilter, setTableCategoryFilter] = useState("ALL");

  const inventorySectionRef = useRef(null);
  const diffFileInputRef = useRef(null);

  const coverage = useMemo(() => scanResults?.coverage || {}, [scanResults]);
  const coverageFailures = coverage?.failures || [];
  const skippedOptionalServices = useMemo(
    () =>
      Array.isArray(coverage?.services_skipped_optional)
        ? coverage.services_skipped_optional
        : (coverage?.service_summary || [])
            .filter((s) => s.status === "SKIPPED_OPTIONAL")
            .map((s) => s.service),
    [coverage]
  );
  const isIncompleteScan =
    coverage?.status === "INCOMPLETE" ||
    scanResults?.partial === true ||
    coverageFailures.length > 0;
  const regionsScanned = coverage?.regions_scanned || scanResults?.regions || [];
  const accountAdvisories = scanResults?.account_advisories || [];

  const handleDiffFileSelected = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setDiffImportError("");
    try {
      const text = await file.text();
      const parsed = parseLocalAssessmentReport(text, file.size);
      if (typeof onImportNewerReport === "function") {
        onImportNewerReport(parsed, file.name);
        setComparisonExpanded(true);
      }
    } catch (err) {
      setDiffImportError(err.message || "Could not import comparison report.");
    } finally {
      if (diffFileInputRef.current) diffFileInputRef.current.value = "";
    }
  };

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
        eval: evaluateCheckStatus(check, allResources, skippedOptionalServices),
      })),
    [activeCatalog, allResources, skippedOptionalServices]
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

  const handleDownloadFullJSON = () => {
    const date = new Date().toISOString().slice(0, 10);
    const filename = `aws-clarity-report-${scanResults?.account_id || "account"}-${date}.json`;
    downloadLocalFile(filename, `${JSON.stringify(scanResults, null, 2)}\n`, "application/json;charset=utf-8;");
    setExportModalOpen(false);
  };

  const handleDownloadSanitizedJSON = () => {
    const sanitized = sanitizeReportForSharing(scanResults);
    const date = new Date().toISOString().slice(0, 10);
    const filename = `aws-clarity-report-sanitized-${date}.json`;
    downloadLocalFile(filename, `${JSON.stringify(sanitized, null, 2)}\n`, "application/json;charset=utf-8;");
    setExportModalOpen(false);
  };

  const handleExportCSV = (sanitized = false) => {
    const sourceResources = sanitized
      ? RESOURCE_COLLECTION_KEYS.flatMap((key) => sanitizeReportForSharing(scanResults)?.resources?.[key] || [])
      : allResources;
    const csvString = buildInventoryCSV(sourceResources, { sanitized });
    const date = new Date().toISOString().slice(0, 10);
    const filename = sanitized
      ? `aws-clarity-inventory-sanitized-${date}.csv`
      : `aws-clarity-inventory-${scanResults?.account_id || "account"}-${date}.csv`;
    downloadLocalFile(filename, csvString, "text/csv;charset=utf-8;");
    setExportModalOpen(false);
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
        <input
          ref={diffFileInputRef}
          type="file"
          accept=".json,application/json"
          onChange={handleDiffFileSelected}
          className="hidden"
        />
        <TopBar
          accountId={scanResults?.account_id || ""}
          regionsCount={regionsScanned.length}
          scannedAt={scanResults?.scanned_at || ""}
          importedFileName={importedFileName}
          isDemoMode={isDemoMode}
          onExitDemo={onExitDemo}
          onTriggerImportNewer={() => diffFileInputRef.current?.click()}
          onReturnHome={onReturnHome}
          onOpenTrust={() => setTrustModalOpen(true)}
        />

        <main className="mt-6 sm:mt-9">
          {diffImportError && (
            <div className="mb-5 flex items-start justify-between gap-3 border border-red-800/40 rounded-xl px-3.5 py-2.5 text-xs text-red-300 bg-red-950/30">
              <span>⚠ {diffImportError}</span>
              <button
                type="button"
                onClick={() => setDiffImportError("")}
                className="text-red-300 hover:text-white bg-transparent border-none p-0 cursor-pointer shrink-0"
              >
                ✕
              </button>
            </div>
          )}

          {/* Unmistakable Demonstration Mode Banner */}
          {isDemoMode && (
            <div className="mb-6 rounded-xl border border-indigo-500/40 bg-indigo-950/30 p-3.5 sm:p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs">
              <div className="space-y-0.5 min-w-0">
                <p className="font-semibold text-indigo-200">
                  Demonstration Account — Sample AWS Assessment Data Only
                </p>
                <p className="text-indigo-200/80 text-[11px] leading-relaxed">
                  You are viewing static synthetic data covering CRITICAL, WARNING, UNUSED, INFO, HEALTHY, and INCOMPLETE
                  states across all 10 supported services. Demo data never mixes with real imported reports.
                </p>
              </div>
              <button
                type="button"
                onClick={onExitDemo}
                className="self-start sm:self-auto shrink-0 px-3.5 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold cursor-pointer transition-colors"
              >
                Import Your Local Report →
              </button>
            </div>
          )}

          {/* Loaded Report Dashboard */}
          {scanResults && (
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
                      : skippedOptionalServices.length > 0
                      ? `Complete Coverage (${10 - skippedOptionalServices.length} of 10 Services · Optional ${skippedOptionalServices.join(", ")} Skipped)`
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
                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setExportModalOpen(true)}
                      disabled={allResources.length === 0}
                      className="text-xs px-3 py-2 sm:py-1.5 rounded-lg border border-teal-500/35 hover:border-teal-400 text-teal-300 hover:text-teal-200 cursor-pointer bg-teal-500/10 transition-colors disabled:opacity-40 shrink-0 font-medium"
                    >
                      Export / Share Report
                    </button>
                  </div>
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
        skippedOptionalServices={skippedOptionalServices}
      />

      {exportModalOpen && (
        <div
          className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-2.5 sm:p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="export-modal-title"
          onClick={(e) => {
            if (e.target === e.currentTarget) setExportModalOpen(false);
          }}
        >
          <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden flex flex-col">
            <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between gap-3">
              <div>
                <h3 id="export-modal-title" className="text-sm sm:text-base font-bold text-white">
                  Export Assessment Locally
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Downloads directly to your computer—nothing is uploaded or shared automatically.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setExportModalOpen(false)}
                aria-label="Close export dialog"
                className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer bg-transparent border-none"
              >
                ✕
              </button>
            </div>
            <div className="p-4 sm:p-5 space-y-4 text-xs">
              <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-500/35 text-amber-200 text-[11px] leading-relaxed">
                <strong>Privacy Warning:</strong> Full AWS Clarity reports contain sensitive infrastructure details
                including <strong>AWS Account IDs</strong>, <strong>Resource ARNs</strong>, <strong>Resource Names</strong>,{" "}
                <strong>Network Configuration</strong>, <strong>Public IP addresses</strong>, and <strong>IAM metadata</strong>.
                Use a <strong>Sanitized Export</strong> before sharing externally or in issue trackers.
              </div>

              <div className="space-y-2">
                <button
                  type="button"
                  onClick={handleDownloadSanitizedJSON}
                  className="w-full text-left p-3 rounded-xl border border-teal-500/40 bg-teal-500/10 hover:bg-teal-500/20 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-teal-200">Download Sanitized JSON (Recommended for Sharing)</p>
                  <p className="text-[11px] text-teal-200/75">
                    Redacts Account IDs, ARNs, resource names, IP addresses, and raw IAM/network payloads while keeping rule IDs, severities, and coverage.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => handleExportCSV(true)}
                  className="w-full text-left p-3 rounded-xl border border-slate-700 bg-slate-950 hover:bg-slate-800/80 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Sanitized CSV</p>
                  <p className="text-[11px] text-slate-400">
                    Spreadsheet inventory with anonymized resource names/IDs and redacted evidence.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadFullJSON}
                  className="w-full text-left p-3 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800/70 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Full JSON Report (Sensitive — Keep Private)</p>
                  <p className="text-[11px] text-slate-400">
                    Complete unredacted local report suitable for private archival or future local Scan Diff.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => handleExportCSV(false)}
                  className="w-full text-left p-3 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800/70 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Full CSV Inventory (Sensitive)</p>
                  <p className="text-[11px] text-slate-400">
                    Complete unredacted spreadsheet of resources, findings, evidence, and remediation steps.
                  </p>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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
