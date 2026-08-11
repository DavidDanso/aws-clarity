import { useState, useEffect, useRef } from "react";
import { maskAccountId } from "../utils/formatters";
import { SUPPORTED_REGIONS } from "../utils/constants";

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

export default function TopBar({
  accountId,
  region,
  scannedAt,
  onRescan,
  isLoading,
  selectedRegions = ["us-east-1"],
  onRegionChange,
  isRescanning = false,
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
        // draftRegions will sync via the other useEffect above
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [popoverOpen]);

  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 px-4 sm:px-6 py-3 w-full bg-transparent">
      {/* Left Slot: Shield icon (14px) + AWS Clarity wordmark (14px) */}
      <div className="flex items-center gap-2">
        <svg className="w-[14px] h-[14px] text-slate-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <span className="text-[14px] font-medium text-slate-200 tracking-tight">AWS Clarity</span>
      </div>

      {/* Center Slot: metadata text (13px, muted color) */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:gap-3 gap-1 text-sm text-slate-400 font-normal">
        {isLoading ? (
          <div className="animate-pulse bg-slate-800 h-3 w-56 rounded" />
        ) : (
          <>
            <span>Account {maskAccountId(accountId)}</span>
            <span className="hidden sm:inline">·</span>
            <div className="relative inline-block" ref={popoverRef}>
              {/* Trigger button */}
              <button
                onClick={() => !isRescanning && setPopoverOpen(prev => !prev)}
                disabled={isRescanning}
                className={`flex items-center gap-1 text-sm transition-opacity ${
                  isRescanning ? "opacity-40 cursor-not-allowed" : "hover:opacity-80"
                }`}
              >
                <span>{selectedRegions?.[0] ?? "us-east-1"}</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  className={`transition-transform duration-200 ${popoverOpen ? "rotate-180" : ""}`}
                >
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </button>

              {/* Popover — right-0 keeps it inside viewport on mobile */}
              {popoverOpen && (
                <div className="absolute top-full mt-2 right-0 z-50 w-64 rounded-lg border border-gray-700 bg-gray-900 shadow-xl p-3">
                  <p className="text-xs text-gray-400 mb-2 font-medium uppercase tracking-wide">
                    Switch Regions
                  </p>
                  <div className="grid grid-cols-1 gap-0.5 max-h-56 overflow-y-auto mb-3 pr-1">
                    {SUPPORTED_REGIONS.map(region => (
                      <label
                        key={region.id}
                        className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer hover:text-white py-1.5 select-none"
                      >
                        <input
                          type="radio"
                          name="dashboard-region"
                          value={region.id}
                          checked={draftRegion === region.id}
                          onChange={() => setDraftRegion(region.id)}
                          className="shrink-0"
                        />
                        {region.label}
                      </label>
                    ))}
                  </div>
                  <div className="flex gap-2 border-t border-gray-700 pt-2">
                    <button
                      onClick={() => setPopoverOpen(false)}
                      className="flex-1 text-sm py-1.5 rounded text-gray-400 hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        setPopoverOpen(false);
                        onRegionChange([draftRegion]);
                      }}
                      className="flex-1 text-sm py-1.5 rounded bg-teal-600 hover:bg-teal-500 text-white font-medium transition-colors"
                    >
                      Apply
                    </button>
                  </div>
                </div>
              )}
            </div>
            <span className="hidden sm:inline">·</span>
            <span>Scanned {getRelativeTime(scannedAt)}</span>
          </>
        )}
      </div>

      {/* Right Slot: Re-scan button — outline only, no fill, 13px, ghost style */}
      <button
        id="rescan-button"
        onClick={onRescan}
        disabled={isLoading}
        className="w-full sm:w-auto px-2.5 py-1 text-[13px] border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white rounded bg-transparent transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Re-scan
      </button>
    </div>
  );
}

