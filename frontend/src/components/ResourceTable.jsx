import { useState, useMemo } from "react";
import { RESOURCE_TYPE_LABELS, STATUS_BADGE } from "../utils/constants";
import { formatCost } from "../utils/formatters";

export default function ResourceTable({
  resources = [],
  onInspect,
  accountId = "",
  resourceLevelEnabled = false,
  hasAnyCost = false,
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [sortKey, setSortKey] = useState(null);
  const [sortDir, setSortDir] = useState("desc");

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  // resources is pre-flattened array with costInfo attached
  const flatList = resources;

  // Apply filters: search query only
  const filtered = useMemo(() => {
    const query = searchQuery.toLowerCase();
    if (!query) return flatList;
    return flatList.filter(
      (r) =>
        r.name.toLowerCase().includes(query) ||
        r.id.toLowerCase().includes(query)
    );
  }, [flatList, searchQuery]);

  const sortedResources = useMemo(() => {
    return [...filtered].sort((a, b) => {
      if (sortKey === "cost") {
        const aAmt = a.costInfo?.amount ?? -1;
        const bAmt = b.costInfo?.amount ?? -1;
        return sortDir === "desc" ? bAmt - aAmt : aAmt - bAmt;
      }
      return 0; // keep existing order for other sort keys
    });
  }, [filtered, sortKey, sortDir]);

  // Export CSV
  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = [
      "Name",
      "ID",
      "Type",
      "Status",
      "Cost / mo",
      "Cost note",
      "Issues Count",
      "Issues Detail",
    ];
    const rows = sortedResources.map((r) =>
      [
        escape(r.name),
        escape(r.id),
        escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
        escape(r.status),
        escape(
          r.costInfo?.amount !== null && r.costInfo?.amount !== undefined
            ? formatCost(r.costInfo.amount)
            : "—"
        ),
        escape(
          r.costInfo?.isExact
            ? "Exact"
            : r.costInfo?.sharedCount > 1
            ? `Estimated (÷${r.costInfo.sharedCount})`
            : "—"
        ),
        escape(r.issues?.length || 0),
        escape(r.issues && r.issues.length > 0 ? r.issues.map((i) => i.message).join("; ") : "None"),
      ].join(",")
    );
    const csvString = [headers.map(escape).join(","), ...rows].join("\n");
    const date = new Date().toISOString().slice(0, 10);
    const filename = `aws-clarity-scan-${accountId || "account"}-${date}.csv`;
    const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Notice above filter row when service-level attribution */}
      {!resourceLevelEnabled && hasAnyCost && (
        <div className="flex items-center gap-2 mb-3 px-1">
          <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-600 shrink-0">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p className="text-xs text-gray-500">
            Costs are estimated by splitting each AWS service total across resources of that type.
            Hover any amount for details. Enable{" "}
            <a
              href="https://console.aws.amazon.com/cost-management/home#/settings"
              target="_blank"
              rel="noopener noreferrer"
              className="text-teal-500 hover:text-teal-400 underline underline-offset-2 transition-colors"
            >
              Resource-level data
            </a>{" "}
            in Cost Explorer for exact per-resource costs.
          </p>
        </div>
      )}

      <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl backdrop-blur-sm overflow-hidden">
        {/* Filters */}
        <div className="flex flex-col gap-2 p-4 border-b border-slate-700/50">
          <div className="flex items-center gap-3 w-full">
            <span className="text-sm text-slate-400 font-medium shrink-0">Search:</span>
            <div className="relative w-full">
              <input
                id="search-input"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by name or ID..."
                className="bg-slate-900 border border-slate-600/50 rounded-lg pl-3 pr-8 py-1.5 text-sm text-slate-300 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 w-full"
              />
              {searchQuery.length > 0 && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer text-sm leading-none"
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto w-full">
          <table className="min-w-[640px] w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-400 border-b border-slate-700/50">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Status</th>
                <th
                  onClick={() => handleSort("cost")}
                  className="text-right pr-3 cursor-pointer select-none hover:text-gray-200 transition-colors whitespace-nowrap hidden sm:table-cell"
                >
                  COST / MO
                  {sortKey === "cost" && (
                    <span className="ml-1 text-teal-400 text-xs">{sortDir === "desc" ? "↓" : "↑"}</span>
                  )}
                </th>
                <th className="px-4 py-3 hidden sm:table-cell">Issues</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {flatList.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-slate-500">
                    No resources discovered in this scan.
                  </td>
                </tr>
              ) : sortedResources.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-slate-500">
                    No resources match the search query.
                  </td>
                </tr>
              ) : (
                sortedResources.map((resource) => (
                  <tr
                    key={resource.id}
                    className="border-b border-slate-700/30 hover:bg-slate-700/20 transition-colors"
                  >
                    <td className="px-4 py-3 font-medium text-slate-200 max-w-[200px] truncate">
                      {resource.name}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                          STATUS_BADGE[resource.status] || STATUS_BADGE.HEALTHY
                        }`}
                      >
                        {resource.status}
                      </span>
                    </td>
                    <td className="text-right pr-3 hidden sm:table-cell">
                      {(() => {
                        const info = resource.costInfo;
                        if (!info || info.amount === null) {
                          return <span className="text-gray-700 text-xs font-mono">—</span>;
                        }
                        return (
                          <div className="flex flex-col items-end">
                            <span
                              className={`text-sm font-mono ${info.amount > 0 ? "text-gray-100" : "text-gray-500"}`}
                              title={
                                info.isExact
                                  ? "Exact cost from AWS Cost Explorer resource-level data"
                                  : info.sharedCount > 1
                                    ? `Estimated: ${info.serviceName} service cost split across ${info.sharedCount} ${RESOURCE_TYPE_LABELS[resource.type] || resource.type} resources`
                                    : `Exact: sole resource using ${info.serviceName}`
                              }
                            >
                              {formatCost(info.amount)}
                            </span>
                            {!info.isExact && info.sharedCount > 1 && (
                              <span className="text-gray-600 text-xs leading-none mt-0.5">
                                ÷{info.sharedCount}
                              </span>
                            )}
                          </div>
                        );
                      })()}
                    </td>
                    <td className="px-4 py-3 text-slate-400 hidden sm:table-cell">
                      {resource.issues?.length || 0}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => onInspect(resource)}
                        className="text-cyan-400 hover:text-cyan-300 text-xs font-medium transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <footer className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm text-slate-500 px-4">
        <span>Read-only access only. No resources are modified.</span>
        <button
          onClick={handleExportCSV}
          className="hover:text-slate-300 transition-colors cursor-pointer underline bg-transparent border-none p-0 w-full sm:w-auto text-left sm:text-right"
        >
          Export CSV
        </button>
      </footer>
    </div>
  );
}
