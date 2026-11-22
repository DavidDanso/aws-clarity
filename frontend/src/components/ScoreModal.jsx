import { useEffect } from "react";

export default function ScoreModal({
  isOpen,
  onClose,
  scoreData,
  coverageFailuresCount = 0,
  skippedOptionalServices = [],
}) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen || !scoreData) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-2.5 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="score-modal-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full max-h-[92dvh] sm:max-h-[90dvh] overflow-hidden flex flex-col shadow-2xl">
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-start sm:items-center justify-between gap-3 shrink-0">
          <div className="min-w-0">
            <h3 id="score-modal-title" className="text-sm sm:text-base font-bold text-white">
              How Your Health Score Is Calculated
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              100% deterministic scoring derived strictly from verified rules
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-9 h-9 sm:w-8 sm:h-8 shrink-0 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer bg-transparent border-none"
            aria-label="Close score explanation modal"
          >
            ✕
          </button>
        </div>

        <div className="p-4 sm:p-5 overflow-y-auto flex-1 space-y-5 text-xs">
          <div className="p-3.5 sm:p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Scoring Formula
            </p>
            <div className="font-mono text-[11px] sm:text-sm text-teal-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800 overflow-x-auto break-words">
              Score = max(0, 100 − [10 × Critical + 4 × Warnings + 1 × Unused])
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Scoring starts at 100 points and subtracts deterministic weights per verified finding.{" "}
              <code className="text-slate-300">INFO</code> review observations deduct <strong>0 points</strong>.
              When any required service, region, or check is <code className="text-orange-300">INCOMPLETE</code>,
              the numeric score is withheld rather than calculated from partial coverage.
            </p>
          </div>

          {!scoreData.isAvailable ? (
            <div className="p-4 rounded-xl bg-orange-950/25 border border-orange-500/35 space-y-2">
              <p className="text-xs font-semibold text-orange-200">
                Health score unavailable — assessment incomplete.
              </p>
              <p className="text-[11px] text-orange-200/80 leading-relaxed">
                {coverageFailuresCount > 0
                  ? `${coverageFailuresCount} collection or check failure${coverageFailuresCount === 1 ? "" : "s"} prevented a complete assessment.`
                  : "One or more resources had incomplete checks."}{" "}
                Resolve the missing permissions or unreachable region issues listed in Scan Coverage and re-scan to compute a full account health score.
              </p>
            </div>
          ) : (
            <div className="p-3.5 sm:p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Live Account Calculation
                </p>
                <span className="text-xs font-mono font-bold text-slate-200">
                  Final Score: <span className="text-teal-400">{scoreData.score} / 100</span> ({scoreData.label})
                </span>
              </div>

              <div className="divide-y divide-slate-800/80 font-mono text-[11px]">
                <div className="py-1.5 flex flex-wrap justify-between gap-x-2">
                  <span className="text-slate-400">Base Starting Score:</span>
                  <span className="text-slate-200">+100 pts</span>
                </div>
                <div className="py-1.5 flex flex-wrap justify-between gap-x-2 text-red-400">
                  <span>Critical Findings ({scoreData.critical} × −10 pts):</span>
                  <span>−{scoreData.critical * 10} pts</span>
                </div>
                <div className="py-1.5 flex flex-wrap justify-between gap-x-2 text-amber-400">
                  <span>Warning Findings ({scoreData.warning} × −4 pts):</span>
                  <span>−{scoreData.warning * 4} pts</span>
                </div>
                <div className="py-1.5 flex flex-wrap justify-between gap-x-2 text-sky-300">
                  <span>Unused Resources ({scoreData.unused} × −1 pt):</span>
                  <span>−{scoreData.unused * 1} pts</span>
                </div>
                <div className="py-1.5 flex flex-wrap justify-between gap-x-2 text-slate-400">
                  <span>Informational Review Notes ({scoreData.info} × 0 pts):</span>
                  <span>0 pts</span>
                </div>
                <div className="py-2 flex flex-wrap justify-between gap-x-2 font-bold text-xs border-t border-slate-700">
                  <span className="text-white font-sans">Calculated Score:</span>
                  <span className="text-teal-300">{scoreData.score} pts</span>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">Total Scanned</span>
              <span className="text-base font-bold text-white font-mono">{scoreData.totalResources}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">Verified Healthy</span>
              <span className="text-base font-bold text-emerald-400 font-mono">{scoreData.healthy}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">Need Attention</span>
              <span className="text-base font-bold text-amber-400 font-mono">{scoreData.needsAttention}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">Cost / Unused</span>
              <span className="text-base font-bold text-sky-300 font-mono">{scoreData.costAndUnusedFindings}</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed space-y-1.5">
            <p className="font-semibold text-slate-300">Important Clarification</p>
            <p>
              This score is an operational visibility metric derived strictly from deterministic checks across executed services. It is not a security certification or compliance audit.
            </p>
            {skippedOptionalServices.length > 0 && (
              <p className="text-sky-300">
                Note: Optional service(s) ({skippedOptionalServices.join(", ")}) were skipped by default to avoid potential AWS API request charges and are <strong>not</strong> treated as healthy.
              </p>
            )}
          </div>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end shrink-0">
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
