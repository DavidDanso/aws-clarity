import { maskAccountId } from "../utils/formatters";

function getRelativeTime(isoString) {
  if (!isoString) return "unknown";
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    
    if (diffMs < 0) {
      return "just now";
    }
    
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) {
      return "just now";
    }
    if (diffMins < 60) {
      return `${diffMins} min${diffMins > 1 ? "s" : ""} ago`;
    }
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) {
      return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
    }
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
  } catch (e) {
    return "unknown";
  }
}

export default function TopBar({ accountId, region, scannedAt, onRescan, isLoading }) {
  return (
    <div className="flex items-center justify-between w-full h-[40px] bg-transparent">
      {/* Left Slot: Shield icon (14px) + AWS Clarity wordmark (14px) */}
      <div className="flex items-center gap-2">
        <svg className="w-[14px] h-[14px] text-slate-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <span className="text-[14px] font-medium text-slate-200 tracking-tight">AWS Clarity</span>
      </div>

      {/* Center Slot: metadata text (13px, muted color) */}
      <div className="text-[13px] text-slate-400 font-normal">
        {isLoading ? (
          <div className="animate-pulse bg-slate-800 h-3 w-56 rounded" />
        ) : (
          `Account ${maskAccountId(accountId)} · ${region} · Scanned ${getRelativeTime(scannedAt)}`
        )}
      </div>

      {/* Right Slot: Re-scan button — outline only, no fill, 13px, ghost style */}
      <button
        id="rescan-button"
        onClick={onRescan}
        disabled={isLoading}
        className="px-2.5 py-1 text-[13px] border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white rounded bg-transparent transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Re-scan
      </button>
    </div>
  );
}

