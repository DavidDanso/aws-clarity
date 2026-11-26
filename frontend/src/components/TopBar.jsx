import { maskAccountId } from "../utils/formatters";

function formatShortTime(isoString) {
  if (!isoString) return "";
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return "";
    const diffMins = Math.floor((Date.now() - date.getTime()) / 60000);
    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  } catch {
    return "";
  }
}

export default function TopBar({
  accountId,
  scannedAt,
  importedFileName = "",
  isDemoMode = false,
  onExitDemo,
  onTriggerImportNewer,
  onOpenExport,
  canExport = false,
  onReturnHome,
  onOpenTrust,
}) {
  const timeLabel = formatShortTime(scannedAt);
  const accountTooltip = [
    importedFileName ? `File: ${importedFileName}` : "",
    timeLabel ? `Generated ${timeLabel}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <header className="flex flex-wrap items-center justify-between gap-2 sm:gap-3 py-3 border-b border-slate-800/70">
      {/* Left: Brand (click to go Home) + Single Calm Context Pill */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <button
          type="button"
          onClick={isDemoMode ? onExitDemo : onReturnHome}
          title="Return to Home & Getting Started"
          className="flex items-center gap-2 shrink-0 bg-transparent border-0 p-0 cursor-pointer group"
        >
          <span
            aria-hidden="true"
            className="w-7 h-7 rounded-lg bg-teal-500/15 border border-teal-500/30 flex items-center justify-center text-teal-400 group-hover:bg-teal-500/25 transition-colors"
          >
            <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </span>
          <span className="text-sm font-semibold text-white tracking-tight group-hover:text-teal-300 transition-colors">
            AWS Clarity
          </span>
        </button>

        <span className="text-slate-700 hidden sm:inline">/</span>

        {isDemoMode ? (
          <span className="text-[11px] font-medium px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 truncate">
            Demo Account
          </span>
        ) : (
          <span
            title={accountTooltip || undefined}
            className="text-xs font-mono text-slate-400 truncate"
          >
            Account {maskAccountId(accountId)}
            {timeLabel && <span className="hidden md:inline text-slate-500"> · {timeLabel}</span>}
          </span>
        )}
      </div>

      {/* Right: Max 3 Clean Actions */}
      <nav aria-label="Dashboard actions" className="flex items-center gap-2 shrink-0">
        {isDemoMode ? (
          <>
            {onOpenTrust && (
              <button
                type="button"
                onClick={onOpenTrust}
                className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white bg-transparent border-0 cursor-pointer transition-colors"
              >
                Privacy
              </button>
            )}
            <button
              type="button"
              onClick={onExitDemo}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 transition-colors cursor-pointer whitespace-nowrap"
            >
              Import My Report →
            </button>
          </>
        ) : (
          <>
            {onOpenTrust && (
              <button
                type="button"
                onClick={onOpenTrust}
                className="px-2 py-1.5 text-xs text-slate-400 hover:text-white bg-transparent border-0 cursor-pointer transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400 hidden sm:inline-block" />
                <span className="sm:hidden">Privacy</span>
                <span className="hidden sm:inline">Trust &amp; Privacy</span>
              </button>
            )}
            {onOpenExport && (
              <button
                type="button"
                onClick={onOpenExport}
                disabled={!canExport}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer disabled:opacity-40 whitespace-nowrap"
              >
                Export
              </button>
            )}
            {onTriggerImportNewer && (
              <button
                id="import-diff-button"
                type="button"
                onClick={onTriggerImportNewer}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-teal-500/40 bg-teal-500/15 hover:bg-teal-500/25 text-teal-200 transition-colors cursor-pointer whitespace-nowrap"
              >
                Compare Scan
              </button>
            )}
          </>
        )}
      </nav>
    </header>
  );
}
