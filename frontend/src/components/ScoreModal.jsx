import { useEffect } from "react";

export default function ScoreModal({ isOpen, onClose, scoreData }) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen || !scoreData) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="score-modal-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 id="score-modal-title" className="text-base font-bold text-white">
              How Your Health Score Is Calculated
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              100% deterministic scoring derived strictly from verified rules
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1 cursor-pointer bg-transparent border-none"
            aria-label="Close score explanation modal"
          >
            ✕
          </button>
        </div>

        <div className="p-5 overflow-y-auto space-y-5 text-xs">
          {/* Formula Card */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Scoring Formula
            </p>
            <div className="font-mono text-xs sm:text-sm text-teal-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
              Score = max(0, 100 − [10 × Critical + 4 × Warnings + 1 × Unused/Orphaned])
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Scoring starts at 100 points and subtracts deterministic weights per detected finding.
              Resources marked <code className="text-slate-300">NOT_ASSESSED</code> are treated neutrally—never penalized and never falsely credited as healthy.
            </p>
          </div>

          {/* Live Calculation */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Live Account Calculation
              </p>
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
              <div className="py-1.5 flex justify-between text-sky-300">
                <span>Unused / Orphaned ({scoreData.orphaned} × −1 pt):</span>
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
            This score is an operational visibility signal based strictly on the deterministic checks performed across supported services. It is not a formal compliance certification (SOC 2, ISO 27001, PCI-DSS, HIPAA, or CIS).
          </div>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
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
