import { useState, useEffect, useRef } from "react";
import { maskAccountId } from "../utils/formatters";
import { SUPPORTED_REGIONS } from "../utils/constants";

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
  scannedAt,
  onRescan,
  onDisconnect,
  isLoading,
  selectedRegions = ["us-east-1"],
  onRegionChange,
  isRescanning = false,
  onOpenTrust,
}) {
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [draftRegion, setDraftRegion] = useState(selectedRegions?.[0] ?? "us-east-1");
  const popoverRef = useRef(null);

  useEffect(() => {
    if (!popoverOpen) {
      setDraftRegion(selectedRegions?.[0] ?? "us-east-1");
    }
  }, [selectedRegions, popoverOpen]);

  useEffect(() => {
    if (!popoverOpen) return;
    const handleClickOutside = (e) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target)) {
        setPopoverOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [popoverOpen]);

  return (
    <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-3 w-full border-b border-slate-800/70">
      {/* Left: Brand */}
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded-md bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
          <svg className="w-3.5 h-3.5 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <span className="text-[14px] font-semibold text-slate-100 tracking-tight">AWS Clarity</span>
      </div>

      {/* Center: Account, Region Switcher, Timestamp */}
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-400">
        {isLoading ? (
          <div className="animate-pulse bg-slate-800 h-3.5 w-52 rounded" />
        ) : (
          <>
            <span className="font-mono text-slate-300">Account {maskAccountId(accountId)}</span>
            <span className="text-slate-700">·</span>
            <div className="relative inline-block" ref={popoverRef}>
              <button
                type="button"
                onClick={() => !isRescanning && setPopoverOpen((prev) => !prev)}
                disabled={isRescanning}
                className={`flex items-center gap-1 text-xs text-slate-300 font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 transition-colors ${
                  isRescanning ? "opacity-40 cursor-not-allowed" : "hover:border-slate-600 cursor-pointer"
                }`}
              >
                <span>{selectedRegions?.[0] ?? "us-east-1"}</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="11"
                  height="11"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  className={`transition-transform duration-200 ${popoverOpen ? "rotate-180" : ""}`}
                >
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </button>

              {popoverOpen && (
                <div className="absolute top-full mt-2 left-0 sm:right-0 sm:left-auto z-50 w-64 rounded-xl border border-slate-700 bg-slate-900 shadow-2xl p-3">
                  <p className="text-[11px] text-slate-400 mb-2 font-semibold uppercase tracking-wide">
                    Switch Region
                  </p>
                  <div className="grid grid-cols-1 gap-0.5 max-h-56 overflow-y-auto mb-3 pr-1">
                    {SUPPORTED_REGIONS.map((r) => (
                      <label
                        key={r.id}
                        className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer hover:text-white py-1.5 select-none"
                      >
                        <input
                          type="radio"
                          name="dashboard-region"
                          value={r.id}
                          checked={draftRegion === r.id}
                          onChange={() => setDraftRegion(r.id)}
                          className="shrink-0 accent-teal-500"
                        />
                        <span>{r.label}</span>
                      </label>
                    ))}
                  </div>
                  <div className="flex gap-2 border-t border-slate-800 pt-2">
                    <button
                      type="button"
                      onClick={() => setPopoverOpen(false)}
                      className="flex-1 text-xs py-1.5 rounded text-slate-400 hover:text-white transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setPopoverOpen(false);
                        onRegionChange([draftRegion]);
                      }}
                      className="flex-1 text-xs py-1.5 rounded bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors cursor-pointer"
                    >
                      Scan Region
                    </button>
                  </div>
                </div>
              )}
            </div>
            {scannedAt && (
              <>
                <span className="text-slate-700">·</span>
                <span>Scanned {getRelativeTime(scannedAt)}</span>
              </>
            )}
          </>
        )}
      </div>

      {/* Right: Actions */}
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
            disabled={isLoading || isRescanning}
            className="px-2.5 py-1 text-xs border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded-md bg-transparent transition-colors cursor-pointer disabled:opacity-40"
          >
            Switch Account
          </button>
        )}
        <button
          id="rescan-button"
          type="button"
          onClick={onRescan}
          disabled={isLoading || isRescanning}
          className="px-3 py-1 text-xs border border-teal-500/40 bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 hover:text-teal-200 font-medium rounded-md transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Re-scan
        </button>
      </div>
    </header>
  );
}
