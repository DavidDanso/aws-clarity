import { maskAccountId } from "../utils/formatters";

function getRelativeTime(isoString) {
  if (!isoString) return "unknown";
  try {
    const date = new Date(isoString);
    const diffMs = Date.now() - date.getTime();
    if (diffMs < 0) return "just now";
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? "s" : ""} ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
  } catch {
    return "unknown";
  }
}

export default function TopBar({
  accountId,
  regionsCount = 0,
  scannedAt,
  onRescan,
  onDisconnect,
  isLoading,
  onOpenTrust,
}) {
  return (
    <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-3 w-full border-b border-slate-800/70">
      {/* Brand */}
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded-md bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
          <svg className="w-3.5 h-3.5 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <span className="text-[14px] font-semibold text-slate-100 tracking-tight">AWS Clarity</span>
      </div>

      {/* Connected Account Metadata */}
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-400">
        {isLoading ? (
          <div className="animate-pulse bg-slate-800 h-3.5 w-56 rounded" />
        ) : (
          <>
            <span className="font-mono text-slate-200">Account {maskAccountId(accountId)}</span>
            {regionsCount > 0 && (
              <>
                <span className="text-slate-700">·</span>
                <span className="font-mono text-slate-300 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                  {regionsCount} enabled region{regionsCount === 1 ? "" : "s"}
                </span>
              </>
            )}
            {scannedAt && (
              <>
                <span className="text-slate-700">·</span>
                <span>Scanned {getRelativeTime(scannedAt)}</span>
              </>
            )}
          </>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-wrap">
        {onOpenTrust && (
          <button
            type="button"
            onClick={onOpenTrust}
            className="px-2.5 py-1 text-xs border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded-md bg-slate-900/60 transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
            <span>Trust</span>
          </button>
        )}
        {onDisconnect && (
          <button
            type="button"
            onClick={onDisconnect}
            disabled={isLoading}
            className="px-2.5 py-1 text-xs border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded-md bg-transparent transition-colors cursor-pointer disabled:opacity-40"
          >
            Switch Account
          </button>
        )}
        <button
          id="rescan-button"
          type="button"
          onClick={onRescan}
          disabled={isLoading}
          className="px-3 py-1 text-xs border border-teal-500/40 bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 hover:text-teal-200 font-medium rounded-md transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Re-scan Account
        </button>
      </div>
    </header>
  );
}
