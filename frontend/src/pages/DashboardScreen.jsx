import { useState, useMemo, useRef } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import ResourceTable from "../components/ResourceTable";
import TrustModal from "../components/TrustModal";
import CoverageModal from "../components/CoverageModal";
import ScoreModal from "../components/ScoreModal";
import ChecksCatalogModal from "../components/ChecksCatalogModal";
import {
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
  const r = 30;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const strokeColor =
    score >= 90 ? "#34d399"
    : score >= 75 ? "#2dd4bf"
    : score >= 50 ? "#fbbf24"
    : score >= 25 ? "#fb923c"
    : "#f87171";

  return (
    <div className="flex items-center gap-4 shrink-0">
      <svg width="68" height="68" viewBox="0 0 72 72" className="-rotate-90 shrink-0" aria-hidden="true">
        <circle cx="36" cy="36" r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
        <circle
          cx="36"
          cy="36"
          r={r}
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
        <span className={`text-3xl font-bold tabular-nums leading-none tracking-tight ${labelColor}`}>
          {score}
          <span className="text-sm font-normal text-slate-500 ml-0.5">/100</span>
        </span>
        <span className={`text-xs font-semibold mt-1 leading-none ${labelColor}`}>{label}</span>
      </div>
    </div>
  );
}

const SEVERITY_DOT = {
  CRITICAL: "bg-red-500",
  WARNING: "bg-amber-400",
  UNUSED: "bg-sky-400",
  INFO: "bg-slate-400",
};

const SEVERITY_TEXT = {
  CRITICAL: "text-red-400",
  WARNING: "text-amber-400",
  UNUSED: "text-sky-300",
  INFO: "text-slate-400",
};

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

  const inventorySectionRef = useRef(null);
  const diffFileInputRef = useRef(null);

  const coverage = useMemo(() => scanResults?.coverage || {}, [scanResults]);
  const coverageFailures = useMemo(() => coverage?.failures || [], [coverage]);
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
  const regionsFailed = coverage?.regions_failed || [];
  const regionsSucceededCount = Math.max(0, regionsScanned.length - regionsFailed.length);
  const accountAdvisories = useMemo(() => scanResults?.account_advisories || [], [scanResults]);

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

  const scoreData = useMemo(
    () => computeScore(allResources, isIncompleteScan, accountAdvisories),
    [allResources, isIncompleteScan, accountAdvisories]
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
        eval: evaluateCheckStatus(
          check,
          allResources,
          skippedOptionalServices,
          coverageFailures,
          coverage?.scanner_statuses || []
        ),
      })),
    [activeCatalog, allResources, skippedOptionalServices, coverageFailures, coverage]
  );

  // Up to 4 highest-priority actionable findings (Critical -> Unused/Cost -> Warning)
  const topPriorityItems = useMemo(() => {
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
        (i.severity === "UNUSED" ||
          i.category === "Potential Cost Waste" ||
          i.category === "Cost Risk"),
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

  const assessedServicesCount = 10 - skippedOptionalServices.length;

  return (
    <div className="min-h-[100dvh] bg-slate-950 text-white">
      <div className="px-4 sm:px-6 lg:px-8 py-3 sm:py-5 pb-20 max-w-6xl mx-auto w-full">
        <input
          ref={diffFileInputRef}
          type="file"
          accept=".json,application/json"
          onChange={handleDiffFileSelected}
          className="hidden"
        />

        <TopBar
          accountId={scanResults?.account_id || ""}
          scannedAt={scanResults?.scanned_at || ""}
          importedFileName={importedFileName}
          isDemoMode={isDemoMode}
          onExitDemo={onExitDemo}
          onTriggerImportNewer={() => diffFileInputRef.current?.click()}
          onOpenExport={() => setExportModalOpen(true)}
          canExport={allResources.length > 0}
          onReturnHome={onReturnHome}
          onOpenTrust={() => setTrustModalOpen(true)}
        />

        <main className="mt-6 space-y-8">
          {/* Import Diff Error */}
          {diffImportError && (
            <div className="flex items-start justify-between gap-3 border border-red-800/50 rounded-xl px-4 py-2.5 text-xs text-red-300 bg-red-950/30">
              <span>⚠ {diffImportError}</span>
              <button
                type="button"
                onClick={() => setDiffImportError("")}
                aria-label="Dismiss error"
                className="text-red-300 hover:text-white bg-transparent border-0 p-0 cursor-pointer shrink-0"
              >
                ✕
              </button>
            </div>
          )}

          {/* Slim Single-Line Demo Notice */}
          {isDemoMode && (
            <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/25 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
              <p className="text-indigo-200">
                <strong className="font-semibold">Demo Mode:</strong> Exploring sample AWS data — nothing here is from your account.
              </p>
              <button
                type="button"
                onClick={onExitDemo}
                className="text-xs font-semibold text-teal-300 hover:text-teal-200 underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer"
              >
                Scan your real AWS account →
              </button>
            </div>
          )}

          {scanResults && (
            <>
              {/* Account-Wide Critical Advisory (e.g. CT-000 No CloudTrail) */}
              {accountAdvisories.length > 0 && (
                <div className="space-y-2.5">
                  {accountAdvisories.map((adv, idx) => (
                    <details
                      key={`${adv.rule_id}-${idx}`}
                      className="clarity-disclosure rounded-xl border border-red-500/35 bg-red-950/20 px-4 py-3 text-xs"
                    >
                      <summary className="text-red-100 font-semibold">
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30 shrink-0">
                          {adv.rule_id}
                        </span>
                        <span className="truncate">{adv.title}</span>
                        <span className="ml-auto text-[11px] font-normal text-red-300/80 shrink-0">
                          View fix
                        </span>
                      </summary>
                      <div className="pt-3 pl-4 space-y-1.5 text-slate-300 leading-relaxed">
                        <p>{adv.why}</p>
                        {adv.impact && (
                          <p className="text-amber-200/90">
                            <strong className="text-amber-300">Impact &amp; Dependencies:</strong> {adv.impact}
                          </p>
                        )}
                        <p className="text-teal-300">
                          <strong className="text-teal-400">Fix:</strong> {adv.fix}
                        </p>
                        <p className="text-emerald-300/90">
                          <strong className="text-emerald-400">Verify:</strong> {adv.verify}
                        </p>
                      </div>
                    </details>
                  ))}
                </div>
              )}

              {/* LEVEL 1 — UNIFIED ACCOUNT OVERVIEW */}
              <section
                aria-label="Account health overview"
                className="rounded-2xl border border-slate-800/90 bg-slate-900/50 p-5 sm:p-6 space-y-5"
              >
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
                  {/* Left: Honest Health Score OR Clear Incomplete Explanation */}
                  {scoreData.isAvailable ? (
                    <div className="space-y-2">
                      <ScoreRing
                        score={scoreData.score}
                        label={scoreData.label}
                        labelColor={scoreData.labelColor}
                      />
                      <button
                        type="button"
                        onClick={() => setScoreModalOpen(true)}
                        className="text-[11px] text-slate-400 hover:text-teal-300 transition-colors bg-transparent border-0 p-0 cursor-pointer"
                      >
                        How this score is calculated →
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-w-md">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full bg-orange-400 shrink-0" />
                        <h1 className="text-sm sm:text-base font-bold text-orange-200">
                          Health score unavailable — assessment incomplete
                        </h1>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {regionsFailed.length > 0
                          ? `${regionsFailed.length} region${regionsFailed.length === 1 ? "" : "s"} couldn't be reached (${regionsFailed.join(", ")}), so we withhold the numeric score rather than guessing.`
                          : `${coverageFailures.length || "Some"} check${coverageFailures.length === 1 ? "" : "s"} couldn't finish, so we withhold the numeric score rather than guessing.`}
                      </p>
                      <button
                        type="button"
                        onClick={() => setCoverageModalOpen(true)}
                        className="text-xs font-semibold text-orange-300 hover:text-orange-200 underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer"
                      >
                        See incomplete regions &amp; details →
                      </button>
                    </div>
                  )}

                  {/* Right: 4 Clean Clickable Stat Tiles */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 w-full md:w-auto md:min-w-[400px]">
                    <button
                      type="button"
                      onClick={() => jumpToInventory("CRITICAL")}
                      className="rounded-xl border border-slate-800 hover:border-red-500/40 bg-slate-950/70 hover:bg-red-950/20 px-3.5 py-3 text-left transition-colors cursor-pointer"
                    >
                      <span className="text-xl sm:text-2xl font-bold tabular-nums text-red-400 block leading-none">
                        {scoreData.critical}
                      </span>
                      <span className="text-[11px] text-slate-400 mt-1.5 block">Critical</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => jumpToInventory("WARNING")}
                      className="rounded-xl border border-slate-800 hover:border-amber-500/40 bg-slate-950/70 hover:bg-amber-950/20 px-3.5 py-3 text-left transition-colors cursor-pointer"
                    >
                      <span className="text-xl sm:text-2xl font-bold tabular-nums text-amber-400 block leading-none">
                        {scoreData.warning}
                      </span>
                      <span className="text-[11px] text-slate-400 mt-1.5 block">Warnings</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => jumpToInventory("COST_UNUSED")}
                      className="rounded-xl border border-slate-800 hover:border-sky-500/40 bg-slate-950/70 hover:bg-sky-950/20 px-3.5 py-3 text-left transition-colors cursor-pointer"
                    >
                      <span className="text-xl sm:text-2xl font-bold tabular-nums text-sky-300 block leading-none">
                        {scoreData.potentialCostWaste}
                      </span>
                      <span className="text-[11px] text-slate-400 mt-1.5 block">Cost / Review</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => jumpToInventory("HEALTHY")}
                      className="rounded-xl border border-slate-800 hover:border-emerald-500/40 bg-slate-950/70 hover:bg-emerald-950/20 px-3.5 py-3 text-left transition-colors cursor-pointer"
                    >
                      <span className="text-xl sm:text-2xl font-bold tabular-nums text-emerald-400 block leading-none">
                        {scoreData.healthy}
                      </span>
                      <span className="text-[11px] text-slate-400 mt-1.5 block">Healthy</span>
                    </button>
                  </div>
                </div>

                {/* Quiet Single-Line Transparency Footer */}
                <div className="pt-3.5 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                    <button
                      type="button"
                      onClick={() => setCoverageModalOpen(true)}
                      className="inline-flex items-center gap-1.5 hover:text-white transition-colors bg-transparent border-0 p-0 cursor-pointer"
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          isIncompleteScan ? "bg-orange-400" : "bg-emerald-400"
                        }`}
                      />
                      <span>
                        {allResources.length} resources · {assessedServicesCount}/10 services
                        {skippedOptionalServices.length > 0 ? ` (${skippedOptionalServices.join(", ")} skipped)` : ""}
                        {regionsScanned.length > 0 ? ` · ${regionsSucceededCount}/${regionsScanned.length} regions` : ""}
                      </span>
                    </button>
                    <span className="text-slate-700">·</span>
                    <button
                      type="button"
                      onClick={() => setCatalogModalOpen(true)}
                      className="hover:text-teal-300 transition-colors bg-transparent border-0 p-0 cursor-pointer"
                    >
                      {activeCatalog.length} rules checked
                    </button>
                    {typeof scanResults?.scan_duration_ms === "number" && (
                      <>
                        <span className="text-slate-700 hidden sm:inline">·</span>
                        <span className="font-mono text-slate-500 hidden sm:inline">
                          {(scanResults.scan_duration_ms / 1000).toFixed(1)}s
                        </span>
                      </>
                    )}
                  </div>

                  {comparison.hasPrevious && (
                    <button
                      type="button"
                      onClick={() => setComparisonExpanded((prev) => !prev)}
                      className="text-xs font-semibold text-teal-300 hover:text-teal-200 bg-teal-500/10 border border-teal-500/30 px-2.5 py-1 rounded-lg cursor-pointer transition-colors"
                    >
                      Scan Diff: {comparison.resolvedCount} resolved · {comparison.newCount} new{" "}
                      {comparisonExpanded ? "▲" : "▼"}
                    </button>
                  )}
                </div>
              </section>

              {/* OPTIONAL SCAN DIFF PANEL (Only visible after user compares two scans) */}
              {comparisonExpanded && comparison.hasPrevious && (
                <section
                  aria-label="Scan comparison diff"
                  className="rounded-2xl border border-teal-500/30 bg-slate-900/60 p-4 sm:p-5 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-sm font-semibold text-white">
                      Changes Since Previous Scan
                    </h2>
                    {scoreData.isAvailable && !previousScanIncomplete && (
                      <span className="text-xs font-mono text-slate-300">
                        Score: {comparison.previousScore} → {comparison.currentScore}{" "}
                        <span
                          className={
                            comparison.scoreDelta > 0
                              ? "text-emerald-400"
                              : comparison.scoreDelta < 0
                              ? "text-red-400"
                              : "text-slate-500"
                          }
                        >
                          ({comparison.scoreDelta > 0 ? `+${comparison.scoreDelta}` : comparison.scoreDelta} pts)
                        </span>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 flex-wrap">
                    {[
                      { key: "resolved", label: "✓ Resolved", count: comparison.resolvedCount, active: "text-emerald-300 bg-emerald-500/15 border-emerald-500/30" },
                      { key: "new", label: "New", count: comparison.newCount, active: "text-cyan-300 bg-cyan-500/15 border-cyan-500/30" },
                      { key: "stillOpen", label: "Unchanged", count: comparison.stillOpenCount, active: "text-amber-300 bg-amber-500/15 border-amber-500/30" },
                      { key: "newResources", label: "Added Resources", count: comparison.newResourcesCount, active: "text-sky-300 bg-sky-500/15 border-sky-500/30" },
                      { key: "removedResources", label: "Removed", count: comparison.removedResourcesCount, active: "text-rose-300 bg-rose-500/15 border-rose-500/30" },
                      { key: "statusChanges", label: "Status Changes", count: comparison.statusChangesCount, active: "text-indigo-300 bg-indigo-500/15 border-indigo-500/30" },
                    ].map((tab) => (
                      <button
                        type="button"
                        key={tab.key}
                        onClick={() => setProgressTab(tab.key)}
                        className={`text-xs font-medium px-2.5 py-1 rounded-lg border transition-colors cursor-pointer flex items-center gap-1.5 ${
                          progressTab === tab.key
                            ? tab.active
                            : "text-slate-400 hover:text-slate-200 border-slate-800 bg-slate-950/50"
                        }`}
                      >
                        <span>{tab.label}</span>
                        <span className="font-mono text-[11px] opacity-80">{tab.count}</span>
                      </button>
                    ))}
                  </div>

                  <div className="text-xs space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {progressTab === "resolved" &&
                      (comparison.resolvedCount === 0 ? (
                        <p className="text-slate-500 py-1">No findings resolved since the previous scan.</p>
                      ) : (
                        comparison.resolved.map((item, idx) => (
                          <div key={idx} className="flex items-center gap-2 py-1.5 px-2.5 rounded-lg bg-emerald-950/25">
                            <span className="text-emerald-400 font-bold shrink-0">✓</span>
                            {item.ruleId && <span className="text-[11px] font-mono text-emerald-400 shrink-0">{item.ruleId}</span>}
                            <span className="text-slate-200 truncate">{item.title}</span>
                            <span className="text-slate-500 text-[11px] truncate ml-auto shrink-0">{item.resourceName}</span>
                          </div>
                        ))
                      ))}
                    {progressTab === "new" &&
                      (comparison.newCount === 0 ? (
                        <p className="text-slate-500 py-1">No new findings discovered.</p>
                      ) : (
                        comparison.newFindings.map((item, idx) => (
                          <div key={idx} className="flex items-center gap-2 py-1.5 px-2.5 rounded-lg bg-cyan-950/25">
                            <span className="text-cyan-400 font-bold shrink-0">+</span>
                            {item.ruleId && <span className="text-[11px] font-mono text-cyan-400 shrink-0">{item.ruleId}</span>}
                            <span className="text-slate-200 truncate">{item.title}</span>
                            <span className="text-slate-500 text-[11px] truncate ml-auto shrink-0">{item.resourceName}</span>
                          </div>
                        ))
                      ))}
                    {progressTab === "stillOpen" &&
                      (comparison.stillOpenCount === 0 ? (
                        <p className="text-slate-500 py-1">No findings carried over.</p>
                      ) : (
                        comparison.stillOpen.map((item, idx) => (
                          <div key={idx} className="flex items-center gap-2 py-1.5 px-2.5 rounded-lg bg-amber-950/20">
                            <span className="text-amber-400 font-bold shrink-0">•</span>
                            {item.ruleId && <span className="text-[11px] font-mono text-amber-400 shrink-0">{item.ruleId}</span>}
                            <span className="text-slate-200 truncate">{item.title}</span>
                            <span className="text-slate-500 text-[11px] truncate ml-auto shrink-0">{item.resourceName}</span>
                          </div>
                        ))
                      ))}
                    {progressTab === "newResources" &&
                      (comparison.newResourcesCount === 0 ? (
                        <p className="text-slate-500 py-1">No new resources discovered.</p>
                      ) : (
                        comparison.newResources.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between py-1.5 px-2.5 rounded-lg bg-sky-950/20">
                            <span className="text-slate-200 truncate">
                              <span className="text-[10px] font-mono text-sky-400 mr-2 uppercase">{item.type}</span>
                              {item.name || item.id}
                            </span>
                            <span className={`text-[11px] font-semibold ${STATUS_COLOR[item.status] || "text-slate-400"}`}>
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
                          <div key={idx} className="flex items-center justify-between py-1.5 px-2.5 rounded-lg bg-rose-950/20">
                            <span className="text-slate-200 truncate">
                              <span className="text-[10px] font-mono text-rose-400 mr-2 uppercase">{item.type}</span>
                              {item.name || item.id}
                            </span>
                            <span className="text-[11px] text-slate-500 font-mono">Removed</span>
                          </div>
                        ))
                      ))}
                    {progressTab === "statusChanges" &&
                      (comparison.statusChangesCount === 0 ? (
                        <p className="text-slate-500 py-1">No resource status changes.</p>
                      ) : (
                        comparison.statusChanges.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between py-1.5 px-2.5 rounded-lg bg-indigo-950/20">
                            <span className="text-slate-200 truncate">{item.resourceName}</span>
                            <span className="flex items-center gap-1.5 shrink-0 text-[11px] font-mono">
                              <span className={STATUS_COLOR[item.previousStatus] || "text-slate-400"}>{item.previousStatus}</span>
                              <span className="text-slate-500">→</span>
                              <span className={STATUS_COLOR[item.currentStatus] || "text-slate-400"}>{item.currentStatus}</span>
                            </span>
                          </div>
                        ))
                      ))}
                  </div>
                </section>
              )}

              {/* LEVEL 2 — WHAT TO FIX FIRST */}
              <section aria-labelledby="priority-heading" className="space-y-3">
                <div className="flex items-baseline justify-between gap-2">
                  <h2 id="priority-heading" className="text-sm font-bold text-white">
                    What to fix first
                  </h2>
                  {topPriorityItems.length > 0 && (
                    <span className="text-xs text-slate-500">
                      Click any item for AWS evidence &amp; step-by-step fix
                    </span>
                  )}
                </div>

                {topPriorityItems.length > 0 ? (
                  <div className="rounded-2xl border border-slate-800/90 bg-slate-900/40 divide-y divide-slate-800/70 overflow-hidden">
                    {topPriorityItems.map(({ resource, issue }, idx) => (
                      <button
                        type="button"
                        key={`${issue.rule_id}-${resource.id}-${idx}`}
                        onClick={() => setSelectedResource(resource)}
                        className="w-full text-left px-4 py-3.5 hover:bg-slate-800/45 transition-colors cursor-pointer flex items-center justify-between gap-4 bg-transparent border-0"
                      >
                        <div className="flex items-start gap-3 min-w-0">
                          <span
                            className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                              SEVERITY_DOT[issue.severity] || "bg-slate-400"
                            }`}
                          />
                          <div className="min-w-0 space-y-0.5">
                            <p className="text-sm font-medium text-slate-100 leading-snug">
                              {issue.title || issue.message}
                            </p>
                            <p className="text-xs text-slate-400 truncate">
                              <span className={`font-semibold ${SEVERITY_TEXT[issue.severity] || "text-slate-400"}`}>
                                {issue.severity}
                              </span>
                              {" · "}
                              {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                              {" · "}
                              <span className="text-slate-300">{resource.name}</span>
                              {" · "}
                              <span className="font-mono text-slate-500">{resource.region || "global"}</span>
                            </p>
                          </div>
                        </div>
                        <span className="text-xs font-semibold text-teal-400 shrink-0 whitespace-nowrap">
                          Fix steps →
                        </span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/15 px-4 py-3 flex items-center gap-2.5 text-xs text-emerald-300">
                    <span className="font-bold">✓</span>
                    <span>
                      {isIncompleteScan
                        ? "No critical or warning findings in completed checks (some regions were incomplete — inspect coverage above)."
                        : "No critical security risks or unused cost waste detected across your scanned services."}
                    </span>
                  </div>
                )}
              </section>

              {/* LEVEL 3 — ALL RESOURCES (Clean, Single-Toolbar Table) */}
              <section ref={inventorySectionRef} aria-labelledby="inventory-heading" className="scroll-mt-6 space-y-3">
                <div className="flex items-baseline justify-between gap-2">
                  <h2 id="inventory-heading" className="text-sm font-bold text-white">
                    All Resources
                  </h2>
                  <span className="text-xs text-slate-500">
                    {allResources.length} discovered
                  </span>
                </div>

                <ResourceTable
                  resources={allResources}
                  initialStatusFilter={tableStatusFilter}
                  onInspect={(resource) => setSelectedResource(resource)}
                />
              </section>
            </>
          )}
        </main>
      </div>

      {/* MODALS & INSPECTION DRAWER */}
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
                  Export Report Locally
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Saves directly to your computer — nothing is uploaded.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setExportModalOpen(false)}
                aria-label="Close export dialog"
                className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer bg-transparent border-0"
              >
                ✕
              </button>
            </div>
            <div className="p-4 sm:p-5 space-y-4 text-xs">
              <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-500/35 text-amber-200 text-[11px] leading-relaxed">
                <strong>Privacy Warning:</strong> Full reports contain sensitive AWS Account IDs, ARNs,
                resource names, public IPs, and IAM metadata. Use a <strong>Sanitized</strong> export
                before sharing externally.
              </div>

              <div className="space-y-2">
                <button
                  type="button"
                  onClick={handleDownloadSanitizedJSON}
                  className="w-full text-left p-3 rounded-xl border border-teal-500/40 bg-teal-500/10 hover:bg-teal-500/20 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-teal-200">Download Sanitized JSON (Recommended for Sharing)</p>
                  <p className="text-[11px] text-teal-200/75">
                    Best-effort redaction of Account IDs, ARNs, names, IPs, and raw payloads while keeping findings and coverage.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => handleExportCSV(true)}
                  className="w-full text-left p-3 rounded-xl border border-slate-700 bg-slate-950 hover:bg-slate-800/80 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Sanitized CSV</p>
                  <p className="text-[11px] text-slate-400">
                    Spreadsheet inventory with anonymized names/IDs and redacted evidence.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadFullJSON}
                  className="w-full text-left p-3 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800/70 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Full JSON (Private Archive / Diff Baseline)</p>
                  <p className="text-[11px] text-slate-400">
                    Complete unredacted local report for private storage or future Scan Diff.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => handleExportCSV(false)}
                  className="w-full text-left p-3 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800/70 transition-colors cursor-pointer space-y-0.5"
                >
                  <p className="font-semibold text-slate-200">Download Full CSV (Private)</p>
                  <p className="text-[11px] text-slate-400">
                    Complete unredacted spreadsheet of resources, findings, evidence, and fixes.
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
