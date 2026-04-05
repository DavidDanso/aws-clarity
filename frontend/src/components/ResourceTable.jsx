import { useState, useMemo, useEffect } from "react";
import { RESOURCE_TYPE_LABELS, STATUS_BADGE } from "../utils/constants";

const getPageNumbers = (current, total) => {
  if (total <= 5) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 3) return [1, 2, 3, 4, 5, "...", total];
  if (current >= total - 2) return [1, "...", total-4, total-3, total-2, total-1, total];
  return [1, "...", current-1, current, current+1, "...", total];
};

export default function ResourceTable({ resources, onInspect, accountId = "", typeFilter, onTypeFilterChange }) {
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // resources is now a pre-flattened array from DashboardScreen
  const flatList = resources;

  // Get unique types and statuses for filter dropdowns
  const uniqueTypes = useMemo(() => [...new Set(flatList.map((r) => r.type))], [flatList]);
  const uniqueStatuses = useMemo(() => [...new Set(flatList.map((r) => r.status))], [flatList]);

  // Apply filters: type → status → search
  const filtered = useMemo(() => {
    const query = searchQuery.toLowerCase();
    return flatList.filter((r) => {
      if (typeFilter !== "ALL" && r.type !== typeFilter) return false;
      if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
      if (query && !(r.name.toLowerCase().includes(query) || r.id.toLowerCase().includes(query))) return false;
      return true;
    });
  }, [flatList, typeFilter, statusFilter, searchQuery]);

  // Pagination
  const totalPages = Math.ceil(filtered.length / pageSize);
  const paginatedResources = filtered.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  // Reset page on filter/search change
  useEffect(() => {
    setCurrentPage(1);
  }, [typeFilter, statusFilter, searchQuery]);

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
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl backdrop-blur-sm overflow-hidden">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 p-4 border-b border-slate-700/50">
        <span className="text-sm text-slate-400 font-medium">Filters:</span>
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
        <select
          id="type-filter"
          value={typeFilter}
          onChange={(e) => onTypeFilterChange(e.target.value)}
          className="bg-slate-900 border border-slate-600/50 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        >
          <option value="ALL">All Types</option>
          {uniqueTypes.map((t) => (
            <option key={t} value={t}>
              {RESOURCE_TYPE_LABELS[t] || t}
            </option>
          ))}
        </select>
        <select
          id="status-filter"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-900 border border-slate-600/50 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        >
          <option value="ALL">All Statuses</option>
          {uniqueStatuses.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <button
          onClick={handleExportCSV}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-300 bg-slate-700/60 border border-slate-600/50 rounded-lg hover:bg-slate-600/60 transition-colors cursor-pointer"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
            <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
            <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
          </svg>
          Export CSV
        </button>
      </div>

      {/* Info bar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-700/30">
        <span className="text-xs text-slate-500">
          {filtered.length === 0
            ? "No resources match your filters"
            : `Showing ${(currentPage - 1) * pageSize + 1}–${Math.min(currentPage * pageSize, filtered.length)} of ${filtered.length} resources`}
        </span>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">Per page:</span>
          <select
            id="page-size"
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
            className="bg-slate-900 border border-slate-600/50 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
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
                  No resources match the selected filters.
                </td>
              </tr>
            ) : (
              paginatedResources.map((resource) => (
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

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-1.5 p-4 border-t border-slate-700/50">
          <button
            onClick={() => setCurrentPage(p => p - 1)}
            disabled={currentPage === 1}
            className="px-3 py-1.5 text-xs text-slate-300 bg-slate-700/40 border border-slate-600/50 rounded-lg hover:bg-slate-600/50 disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            Previous
          </button>
          {getPageNumbers(currentPage, totalPages).map((page, idx) =>
            page === "..." ? (
              <span key={`ellipsis-${idx}`} className="px-2 py-1.5 text-xs text-slate-500">
                …
              </span>
            ) : (
              <button
                key={page}
                onClick={() => setCurrentPage(page)}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors cursor-pointer ${
                  page === currentPage
                    ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/30 font-semibold"
                    : "text-slate-300 bg-slate-700/40 border-slate-600/50 hover:bg-slate-600/50"
                }`}
              >
                {page}
              </button>
            )
          )}
          <button
            onClick={() => setCurrentPage(p => p + 1)}
            disabled={currentPage === totalPages}
            className="px-3 py-1.5 text-xs text-slate-300 bg-slate-700/40 border border-slate-600/50 rounded-lg hover:bg-slate-600/50 disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
