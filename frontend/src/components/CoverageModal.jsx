import { useEffect } from "react";

const DEFAULT_UNSUPPORTED = [
  { service: "AWS Cost Explorer & Billing APIs", reason: "Deliberately excluded to keep scanning 100% free — Cost Explorer charges $0.01 per API call. AWS Clarity detects cost risks from free configuration metadata instead." },
  { service: "CloudTrail & CloudWatch Logs", reason: "AWS Clarity performs point-in-time configuration inspection, not continuous log ingestion." },
  { service: "Amazon GuardDuty / Security Hub / AWS Config", reason: "Paid security services are not queried to avoid incurring unexpected AWS charges." },
  { service: "EKS, ECS, Redshift, ElastiCache & Specialized Services", reason: "Intentionally out of scope in v1 so the scanner remains focused, fast, and transparent across commonly used AWS services." },
  { service: "Customer Data Contents", reason: "AWS Clarity never reads S3 object contents, database records, or application payloads." },
];

export default function CoverageModal({
  isOpen,
  onClose,
  coverage = {},
  permissionChecks = {},
  scannerStatuses = [],
  completedScanners = [],
  failedScanners = [],
  servicesCount = 0,
  allResourcesCount = 0,
  regionDisplay = "us-east-1",
}) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="coverage-modal-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div>
            <h3 id="coverage-modal-title" className="text-base font-bold text-white">
              Scan Coverage & Limitations
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Complete transparency into what AWS Clarity inspected and what is intentionally out of scope.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close coverage modal"
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
              <p className="text-xs font-bold text-slate-200 mt-0.5 truncate">
                {coverage?.regions_scanned?.join(", ") || regionDisplay}
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Services Checked</p>
              <p className="text-xs font-bold text-teal-400 mt-0.5">{servicesCount}</p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
              <p className="text-[10px] uppercase font-semibold text-slate-500">Resources Inspected</p>
              <p className="text-xs font-bold text-slate-200 mt-0.5">
                {coverage?.resources_inspected ?? allResourcesCount}
              </p>
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
                          <span className={`text-[10px] font-mono px-1 rounded ${
                            isOk ? "text-emerald-400 bg-emerald-500/10" : "text-amber-400 bg-amber-500/10"
                          }`}>
                            {isOk ? "Verified" : "Missing"}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5 leading-tight">{info.capability}</p>
                        {!isOk && (
                          <p className="text-[10px] text-amber-300 font-mono mt-1">
                            Requires: {info.required_permission}
                          </p>
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
                Supported Scanners ({scannerStatuses.length || 14} resource types)
              </h4>
              <span className="text-[10px] text-slate-500">
                {completedScanners.length} completed
                {failedScanners.length > 0 ? ` · ${failedScanners.length} partial/failed` : ""}
              </span>
            </div>
            <div className="max-h-52 overflow-y-auto rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 pr-1">
              {scannerStatuses.length > 0 ? (
                scannerStatuses.map((s, idx) => {
                  const isOk = s.status === "COMPLETED";
                  return (
                    <div key={`${s.key}-${s.region}-${idx}`} className="p-2 flex items-center justify-between gap-2 text-[11px]">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={isOk ? "text-emerald-400" : "text-amber-400"}>
                          {isOk ? "✓" : "⚠"}
                        </span>
                        <span className="text-slate-300 font-medium truncate">{s.label || s.service}</span>
                        <span className="text-[10px] text-slate-500 font-mono">({s.region || "global"})</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {isOk ? (
                          <span className="text-slate-400 tabular-nums">{s.count ?? 0} found</span>
                        ) : (
                          <span className="text-amber-400/90 text-[10px] truncate max-w-[160px]" title={s.reason}>
                            {s.reason || "Skipped"}
                          </span>
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
                  Read-only configuration inspection performed across supported AWS services.
                </div>
              )}
            </div>
          </div>

          {/* Out of Scope */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
              What AWS Clarity Does NOT Inspect (Out of Scope)
            </h4>
            <div className="rounded-lg bg-slate-950 border border-slate-800 divide-y divide-slate-800/60 overflow-hidden">
              {(coverage?.unsupported_services || DEFAULT_UNSUPPORTED).map((item, idx) => (
                <div key={idx} className="p-2.5 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1">
                  <span className="font-semibold text-slate-300 shrink-0">{item.service}</span>
                  <span className="text-slate-500 text-[11px] sm:text-right">{item.reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">
            Point-in-time read-only inspection · Zero resources modified · Zero paid APIs
          </span>
          <button
            type="button"
            onClick={onClose}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-1.5 rounded-lg transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
