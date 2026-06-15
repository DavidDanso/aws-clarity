import { useState, useMemo } from "react";
import { RESOURCE_TYPE_LABELS, STATUS_BADGE } from "../utils/constants";

export default function ResourceTable({ resources, onInspect, accountId = "" }) {
  const [searchQuery, setSearchQuery] = useState("");

  // resources is now a pre-flattened array from DashboardScreen
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

  // Export CSV
  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = ["Name", "ID", "Type", "Status", "Issues Count", "Issues Detail"];
    const rows = filtered.map(r => [
      escape(r.name),
      escape(r.id),
      escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
      escape(r.status),
      escape(r.issues.length),
      escape(r.issues.length > 0 ? r.issues.map(i => i.message).join("; ") : "None"),
    ].join(","));
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
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl backdrop-blur-sm overflow-hidden">
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 p-4 border-b border-slate-700/50">
          <span className="text-sm text-slate-400 font-medium">Search:</span>
          <div className="relative">
            <input
              id="search-input"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by name or ID..."
              className="bg-slate-900 border border-slate-600/50 rounded-lg pl-3 pr-8 py-1.5 text-sm text-slate-300 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 w-52"
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

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-400 border-b border-slate-700/50">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Issues</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {flatList.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                    No resources discovered in this scan.
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                    No resources match the search query.
                  </td>
                </tr>
              ) : (
                filtered.map((resource) => (
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
                    <td className="px-4 py-3 text-slate-400">
                      {resource.issues.length}
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
      <footer className="flex justify-between items-center text-xs text-slate-500 px-4">
        <span>Read-only access only. No resources are modified.</span>
        <button
          onClick={handleExportCSV}
          className="hover:text-slate-300 transition-colors cursor-pointer underline bg-transparent border-none p-0"
        >
          Export CSV
        </button>
      </footer>
    </div>
  );
}
