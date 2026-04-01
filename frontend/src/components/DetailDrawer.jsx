import { useEffect, useRef } from "react";

const SEVERITY_STYLE = {
  CRITICAL: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  WARNING: { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30" },
};

const STATUS_COLOR = {
  CRITICAL: "text-red-400",
  WARNING: "text-amber-400",
  HEALTHY: "text-emerald-400",
  ORPHANED: "text-slate-400",
};

// Keys to skip when rendering raw metadata
const RAW_SKIP_KEYS = ["tags", "security_groups", "attachments", "inline_policies"];

export default function DetailDrawer({ resource, onClose }) {
  const drawerRef = useRef(null);

  // Close on click outside
  useEffect(() => {
    const handleClick = (e) => {
      if (drawerRef.current && !drawerRef.current.contains(e.target)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [onClose]);

  // Close on Escape
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose]);

  if (!resource) return null;

  const rawEntries = Object.entries(resource.raw || {}).filter(
    ([key]) => !RAW_SKIP_KEYS.includes(key)
  );

  return (
    <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm">
      <div
        ref={drawerRef}
        className="absolute right-0 top-0 h-full w-full max-w-lg bg-slate-900 border-l border-slate-700/50 shadow-2xl overflow-y-auto animate-slide-in"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-700/50">
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-bold text-white truncate">{resource.name}</h2>
            <p className="text-xs text-slate-500 mt-1 font-mono truncate">{resource.id}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-4 p-2 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Type & Status */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-xs text-slate-500 uppercase tracking-wider">Type</span>
              <p className="text-sm text-slate-200 mt-1">{resource.type}</p>
            </div>
            <div>
              <span className="text-xs text-slate-500 uppercase tracking-wider">Status</span>
              <p className={`text-sm font-semibold mt-1 ${STATUS_COLOR[resource.status] || "text-slate-200"}`}>
                {resource.status}
              </p>
            </div>
          </div>

          {/* Issues */}
          <div>
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Issues ({resource.issues.length})
            </h3>
            {resource.issues.length === 0 ? (
              <p className="text-sm text-slate-500">No issues detected.</p>
            ) : (
              <div className="space-y-3">
                {resource.issues.map((issue, idx) => {
                  const style = SEVERITY_STYLE[issue.severity] || SEVERITY_STYLE.WARNING;
                  return (
                    <div
                      key={idx}
                      className={`rounded-lg border p-4 ${style.bg} ${style.border}`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-bold uppercase ${style.color}`}>
                          {issue.severity}
                        </span>
                      </div>
                      <p className="text-sm text-slate-200">{issue.message}</p>
                      {issue.fix && (
                        <p className="text-xs text-slate-400 mt-2">
                          <span className="font-semibold text-slate-300">Fix: </span>
                          {issue.fix}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Raw Metadata */}
          {rawEntries.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Metadata</h3>
              <div className="bg-slate-800/80 rounded-lg border border-slate-700/50 divide-y divide-slate-700/30">
                {rawEntries.map(([key, value]) => (
                  <div key={key} className="flex justify-between px-4 py-2.5 text-sm">
                    <span className="text-slate-400">{key}</span>
                    <span className="text-slate-200 text-right max-w-[200px] truncate font-mono text-xs">
                      {String(value ?? "—")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
