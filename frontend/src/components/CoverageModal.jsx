import { useEffect } from "react";
import { SERVICE_COVERAGE_MATRIX } from "../utils/constants";

export default function CoverageModal({
  isOpen,
  onClose,
  coverage = {},
  allResourcesCount = 0,
}) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const isIncomplete = coverage?.status === "INCOMPLETE" || coverage?.is_partial;
  const failures = coverage?.failures || [];
  const serviceSummary = coverage?.service_summary || [];
  const optionalChecks = Array.isArray(coverage?.optional_checks) ? coverage.optional_checks : [];
  const skippedOptionalChecks = optionalChecks.filter((item) => item?.status === "SKIPPED_OPTIONAL");
  const regionsScanned = coverage?.regions_scanned || [];
  const regionsFailed =
    coverage?.regions_failed ||
    Array.from(new Set(failures.map((f) => f.region).filter((r) => regionsScanned.includes(r))));
  const regionsSucceeded =
    coverage?.regions_succeeded ||
    regionsScanned.filter((r) => !regionsFailed.includes(r));
  const servicesCompleteCount = serviceSummary.filter((s) => s.status === "COMPLETE").length;
  const servicesSkippedCount = serviceSummary.filter((s) => s.status === "SKIPPED_OPTIONAL").length;
  const servicesAssessedTotal = Math.max(1, (serviceSummary.length || 10) - servicesSkippedCount);

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-2.5 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="coverage-modal-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-3xl w-full max-h-[92dvh] sm:max-h-[88dvh] overflow-hidden flex flex-col">
        <div className="flex items-start sm:items-center justify-between gap-3 p-4 sm:p-5 border-b border-slate-800 shrink-0">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 id="coverage-modal-title" className="text-sm sm:text-base font-bold text-white">
                Inventory Coverage &amp; Scan Transparency
              </h3>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${
                isIncomplete
                  ? "bg-orange-500/15 text-orange-300 border-orange-500/30"
                  : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
              }`}>
                {isIncomplete ? "INCOMPLETE" : "COMPLETE"}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inventory coverage is tracked strictly separately from security findings.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close coverage modal"
            className="w-9 h-9 sm:w-8 sm:h-8 shrink-0 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div className="p-4 sm:p-5 overflow-y-auto flex-1 space-y-5 text-xs">
          {/* Top Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Regions Completed</p>
              <p className="text-sm font-bold text-slate-100 mt-0.5">
                {regionsSucceeded.length} / {regionsScanned.length}
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Services Complete</p>
              <p className="text-sm font-bold text-teal-400 mt-0.5">
                {serviceSummary.length > 0 ? `${servicesCompleteCount} / ${servicesAssessedTotal}` : "10 / 10"}
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Resources Discovered</p>
              <p className="text-sm font-bold text-slate-100 mt-0.5">
                {coverage?.resources_inspected ?? allResourcesCount}
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Collection Failures</p>
              <p className={`text-sm font-bold mt-0.5 ${failures.length > 0 ? "text-orange-400" : "text-emerald-400"}`}>
                {failures.length}
              </p>
            </div>
          </div>

          {/* Explicit Coverage Failures (if any) */}
          {failures.length > 0 && (
            <div>
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-orange-400 mb-2">
                Incomplete Regions, Services & Permission Failures ({failures.length})
              </h4>
              <div className="max-h-52 overflow-y-auto rounded-lg bg-orange-950/20 border border-orange-500/30 divide-y divide-orange-500/20">
                {failures.map((f, idx) => (
                  <div key={idx} className="p-2.5 space-y-1 text-[11px]">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="font-semibold text-orange-200 break-words">
                        {f.service} · {f.label}
                      </span>
                      <span className="font-mono text-[10px] text-orange-300 bg-orange-950/60 px-1.5 py-0.5 rounded shrink-0">
                        {f.region}
                      </span>
                    </div>
                    <p className="text-orange-200/80 break-words">{f.reason}</p>
                    {f.required_permission && (
                      <p className="text-[10px] font-mono text-slate-400 break-all">
                        Required IAM action(s): {f.required_permission}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Intentionally Skipped Optional Checks (distinct from failures and healthy) */}
          {skippedOptionalChecks.length > 0 && (
            <div>
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-sky-300 mb-2">
                Skipped Optional Checks — Not Marked Healthy ({skippedOptionalChecks.length})
              </h4>
              <div className="rounded-lg bg-sky-950/20 border border-sky-500/30 divide-y divide-sky-500/20">
                {skippedOptionalChecks.map((opt, idx) => (
                  <div key={idx} className="p-2.5 space-y-1 text-[11px]">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="font-semibold text-sky-200">{opt.service}</span>
                      <span className="font-mono text-[10px] text-sky-300 bg-sky-950/60 px-1.5 py-0.5 rounded">
                        SKIPPED_OPTIONAL
                      </span>
                    </div>
                    <p className="text-sky-200/80 leading-relaxed">{opt.reason}</p>
                    {opt.opt_in_command && (
                      <p className="text-[10px] font-mono text-slate-400 break-all">
                        Opt in: {opt.opt_in_command}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 10-Service Resource Coverage Matrix */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
              10-Service Resource Coverage Matrix
            </h4>
            <div className="rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 overflow-hidden">
              {(serviceSummary.length > 0
                ? serviceSummary
                : SERVICE_COVERAGE_MATRIX.map((m) => ({
                    service: m.service,
                    scope: m.scope,
                    status: "COMPLETE",
                    resource_count: 0,
                    failure_count: 0,
                    resource_types: m.resources.map((label) => ({ label })),
                  }))
              ).map((svc) => {
                const ok = svc.status === "COMPLETE";
                const skipped = svc.status === "SKIPPED_OPTIONAL";
                return (
                  <div key={svc.service} className="p-2.5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-[11px]">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={ok ? "text-emerald-400 font-bold" : skipped ? "text-sky-300 font-bold" : "text-orange-400 font-bold"}>
                          {ok ? "✓" : skipped ? "○" : "⚠"}
                        </span>
                        <span className="font-semibold text-slate-200">{svc.service}</span>
                        <span className="text-[10px] text-slate-500">({svc.scope})</span>
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5 pl-5">
                        Resource types: {(svc.resource_types || []).map((rt) => rt.label).join(", ")}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 pl-5 sm:pl-0 shrink-0">
                      <span className="text-slate-400 font-mono">{skipped ? "skipped" : `${svc.resource_count} found`}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                        ok
                          ? "text-emerald-400 bg-emerald-500/10"
                          : skipped
                          ? "text-sky-300 bg-sky-500/15"
                          : "text-orange-300 bg-orange-500/15"
                      }`}>
                        {skipped ? "SKIPPED (OPTIONAL)" : svc.status}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Regions Scanned — clearly split between Succeeded vs Inaccessible/Failed */}
          {regionsScanned.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Enabled AWS Regions ({regionsSucceeded.length} completed · {regionsFailed.length} incomplete/inaccessible)
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {regionsScanned.map((reg) => {
                  const isFailed = regionsFailed.includes(reg);
                  return (
                    <span
                      key={reg}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isFailed
                          ? "bg-orange-950/40 border-orange-500/40 text-orange-300"
                          : "bg-slate-950 border-slate-800 text-slate-300"
                      }`}
                    >
                      {isFailed ? `⚠ ${reg}` : `✓ ${reg}`}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Out of Scope */}
          {Array.isArray(coverage?.unsupported_services) && coverage.unsupported_services.length > 0 && (
            <div>
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Intentionally Out of Scope (v1)
              </h4>
              <div className="rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 overflow-hidden">
                {coverage.unsupported_services.map((item, idx) => (
                  <div key={idx} className="p-2.5 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1">
                    <span className="font-semibold text-slate-300 shrink-0">{item.service}</span>
                    <span className="text-slate-500 text-[11px] sm:text-right">{item.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 shrink-0">
          <span className="text-[11px] text-slate-500">
            Strictly read-only · Full API pagination · Zero paid AWS APIs
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
