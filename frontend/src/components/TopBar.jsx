import { maskAccountId, formatTimestamp } from "../utils/formatters";

export default function TopBar({ accountId, region, scannedAt, onRescan }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-800/60 border border-slate-700/50 rounded-2xl backdrop-blur-sm px-6 py-4">
      {/* Left — App name */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
          <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <span className="text-lg font-bold text-white tracking-tight">AWS Clarity</span>
      </div>

      {/* Center — Metadata */}
      <div className="flex items-center gap-6 text-sm">
        <div>
          <span className="text-slate-500 text-xs uppercase tracking-wider">Account</span>
          <p className="text-slate-300 font-mono">{maskAccountId(accountId)}</p>
        </div>
        <div className="hidden sm:block w-px h-8 bg-slate-700" />
        <div className="hidden sm:block">
          <span className="text-slate-500 text-xs uppercase tracking-wider">Region</span>
          <p className="text-slate-300">{region}</p>
        </div>
        <div className="hidden sm:block w-px h-8 bg-slate-700" />
        <div className="hidden sm:block">
          <span className="text-slate-500 text-xs uppercase tracking-wider">Scanned</span>
          <p className="text-slate-300">{formatTimestamp(scannedAt)}</p>
        </div>
      </div>

      {/* Right — Re-scan */}
      <button
        id="rescan-button"
        onClick={onRescan}
        className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-sm font-medium text-slate-200 transition-colors cursor-pointer flex items-center gap-2"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Re-scan
      </button>
    </div>
  );
}
