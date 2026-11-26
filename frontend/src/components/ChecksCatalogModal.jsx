import { useMemo, useRef, useState } from "react";
import { CATEGORY_BADGE } from "../utils/constants";
import { useDialogFocus } from "../utils/useDialogFocus";

export default function ChecksCatalogModal({ isOpen, onClose, evaluatedChecks = [] }) {
  const dialogRef = useRef(null);
  const [catalogFilter, setCatalogFilter] = useState("all");
  const [catalogSearch, setCatalogSearch] = useState("");

  useDialogFocus(isOpen, onClose, dialogRef);

  const checkCounts = useMemo(() => ({
    total: evaluatedChecks.length,
    violated: evaluatedChecks.filter((c) => c.eval.status === "VIOLATED").length,
    review: evaluatedChecks.filter((c) => c.eval.status === "REVIEW").length,
    passed: evaluatedChecks.filter((c) => c.eval.status === "PASSED").length,
    failed: evaluatedChecks.filter((c) => c.eval.status === "CHECK_FAILED").length,
    skippedOptional: evaluatedChecks.filter((c) => c.eval.status === "SKIPPED_OPTIONAL").length,
    na: evaluatedChecks.filter((c) => c.eval.status === "NOT_APPLICABLE").length,
  }), [evaluatedChecks]);

  const filteredChecks = useMemo(() => {
    let list = evaluatedChecks;
    if (catalogFilter === "violated") list = list.filter((c) => c.eval.status === "VIOLATED");
    else if (catalogFilter === "review") list = list.filter((c) => c.eval.status === "REVIEW");
    else if (catalogFilter === "passed") list = list.filter((c) => c.eval.status === "PASSED");
    else if (catalogFilter === "failed") list = list.filter((c) => c.eval.status === "CHECK_FAILED");
    else if (catalogFilter === "skippedOptional") list = list.filter((c) => c.eval.status === "SKIPPED_OPTIONAL");
    else if (catalogFilter === "na") list = list.filter((c) => c.eval.status === "NOT_APPLICABLE");

    if (catalogSearch.trim()) {
      const q = catalogSearch.toLowerCase().trim();
      list = list.filter(
        (c) =>
          c.name.toLowerCase().includes(q) ||
          c.id.toLowerCase().includes(q) ||
          c.service.toLowerCase().includes(q) ||
          (c.category || "").toLowerCase().includes(q) ||
          c.whatItChecks.toLowerCase().includes(q)
      );
    }
    return list;
  }, [evaluatedChecks, catalogFilter, catalogSearch]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-2.5 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="checks-catalog-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[92dvh] sm:max-h-[90dvh] overflow-hidden flex flex-col shadow-2xl focus:outline-none"
      >
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-start sm:items-center justify-between gap-3 shrink-0">
          <div className="min-w-0">
            <h3 id="checks-catalog-title" className="text-sm sm:text-base font-bold text-white">
              Security &amp; Cost Checks Catalog
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {evaluatedChecks.length} deterministic rules across all 10 supported AWS services
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-9 h-9 sm:w-8 sm:h-8 shrink-0 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer bg-transparent border-none"
            aria-label="Close checks catalog modal"
          >
            ✕
          </button>
        </div>

        <div className="px-4 sm:px-5 pt-3.5 pb-3 border-b border-slate-800 space-y-3 bg-slate-950/40 shrink-0">
          <label htmlFor="checks-catalog-search" className="sr-only">
            Filter checks by rule ID, name, service, or category
          </label>
          <input
            id="checks-catalog-search"
            type="text"
            value={catalogSearch}
            onChange={(e) => setCatalogSearch(e.target.value)}
            placeholder="Filter checks by rule ID, name, service, or category…"
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 sm:py-1.5 text-base sm:text-xs text-slate-200 placeholder-slate-400 focus:border-teal-500 transition-colors"
          />

          <div className="flex items-center gap-1.5 overflow-x-auto sm:overflow-visible sm:flex-wrap pb-0.5 sm:pb-0 no-scrollbar">
            {[
              { key: "all", label: "All Checks", count: checkCounts.total },
              { key: "violated", label: "Violated", count: checkCounts.violated, activeClass: "text-red-400 bg-red-500/10 border-red-500/20" },
              ...(checkCounts.review > 0
                ? [{ key: "review", label: "Review Info", count: checkCounts.review, activeClass: "text-slate-200 bg-slate-600/20 border-slate-500/30" }]
                : []),
              { key: "passed", label: "Passed", count: checkCounts.passed, activeClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
              ...(checkCounts.failed > 0
                ? [{ key: "failed", label: "Check Failed", count: checkCounts.failed, activeClass: "text-orange-300 bg-orange-500/10 border-orange-500/20" }]
                : []),
              ...(checkCounts.skippedOptional > 0
                ? [{ key: "skippedOptional", label: "Skipped (Optional)", count: checkCounts.skippedOptional, activeClass: "text-sky-300 bg-sky-500/10 border-sky-500/20" }]
                : []),
              { key: "na", label: "No Resources", count: checkCounts.na, activeClass: "text-slate-300 bg-slate-500/10 border-slate-500/20" },
            ].map((tab) => (
              <button
                type="button"
                key={tab.key}
                onClick={() => setCatalogFilter(tab.key)}
                className={`shrink-0 whitespace-nowrap text-[11px] font-semibold px-2.5 py-1.5 sm:py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 border ${
                  catalogFilter === tab.key
                    ? tab.activeClass || "text-teal-400 bg-teal-500/10 border-teal-500/20"
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

        <div className="p-4 sm:p-5 overflow-y-auto space-y-3 text-xs flex-1">
          {filteredChecks.length === 0 ? (
            <div className="text-center py-8 text-slate-500">No checks match the current filter.</div>
          ) : (
            filteredChecks.map((check) => {
              const status = check.eval.status;
              const isViolated = status === "VIOLATED";
              const isReview = status === "REVIEW";
              const isPassed = status === "PASSED";
              const isFailed = status === "CHECK_FAILED";
              const isSkippedOptional = status === "SKIPPED_OPTIONAL";

              return (
                <div
                  key={check.id}
                  className={`p-3.5 rounded-xl border ${
                    isViolated ? "border-red-500/30 bg-red-950/10" : "border-slate-800 bg-slate-950/60"
                  } space-y-2`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap min-w-0">
                      <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {check.id}
                      </span>
                      <span className="font-semibold text-slate-100 text-xs break-words">
                        {check.service} — {check.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0 flex-wrap">
                      {check.category && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          CATEGORY_BADGE[check.category] || "bg-slate-800 text-slate-400 border-slate-700"
                        }`}>
                          {check.category}
                        </span>
                      )}
                      <span className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                        check.severity === "CRITICAL"
                          ? "text-red-400 bg-red-500/10"
                          : check.severity === "WARNING"
                          ? "text-amber-400 bg-amber-500/10"
                          : "text-sky-300 bg-sky-500/10"
                      }`}>
                        {check.severity}
                      </span>
                    </div>
                  </div>

                  <p className="text-slate-400 text-[11px] leading-relaxed">{check.whatItChecks}</p>

                  <div className="flex flex-wrap items-center justify-between gap-1.5 pt-1 text-[11px] border-t border-slate-800/60">
                    <span className="text-slate-500">Live Status:</span>
                    <div className="flex items-center gap-1.5">
                      {isViolated && (
                        <span className="font-medium text-red-400 flex items-center gap-1">
                          <span>⚠ Violated</span>
                          <span className="font-mono text-[10px] text-red-300">({check.eval.label})</span>
                        </span>
                      )}
                      {isReview && (
                        <span className="font-medium text-slate-300 flex items-center gap-1">
                          <span>ℹ Review</span>
                          <span className="font-mono text-[10px] text-slate-400">({check.eval.label})</span>
                        </span>
                      )}
                      {isPassed && (
                        <span className="font-medium text-emerald-400 flex items-center gap-1">
                          <span>✓ Passed</span>
                          <span className="font-mono text-[10px] text-emerald-500">({check.eval.label})</span>
                        </span>
                      )}
                      {isFailed && (
                        <span className="font-medium text-orange-300 flex items-center gap-1">
                          <span>! Check Failed</span>
                          <span className="font-mono text-[10px] text-orange-200">({check.eval.label})</span>
                        </span>
                      )}
                      {isSkippedOptional && (
                        <span className="font-medium text-sky-300 flex items-center gap-1">
                          <span>○ Skipped (Optional)</span>
                          <span className="font-mono text-[10px] text-sky-200/80">(not evaluated)</span>
                        </span>
                      )}
                      {!isViolated && !isReview && !isPassed && !isFailed && !isSkippedOptional && (
                        <span className="text-slate-500 font-mono text-[10px]">— No resources in account</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 shrink-0">
          <span className="text-[11px] text-slate-500">
            Deterministic rules backed by real AWS API evidence
          </span>
          <button
            type="button"
            onClick={onClose}
            className="w-full sm:w-auto bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-2 sm:py-1.5 rounded-lg transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
