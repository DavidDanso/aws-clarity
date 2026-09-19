import { useState, useMemo, useEffect } from "react";
import { RESOURCE_TYPE_LABELS, STATUS_BADGE } from "../utils/constants";

const PAGE_SIZE = 5;

function getPageNumbers(current, total) {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  if (current <= 4) {
    return [1, 2, 3, 4, 5, "...", total];
  }
  if (current >= total - 3) {
    return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  }
  return [1, "...", current - 1, current, current + 1, "...", total];
}

export default function ResourceTable({
  resources = [],
  onInspect,
  accountId = "",
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);

  const flatList = resources;

  // 1. Filter
  const filtered = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    if (!query) return flatList;
    return flatList.filter(
      (r) =>
        r.name.toLowerCase().includes(query) ||
        r.id.toLowerCase().includes(query)
    );
  }, [flatList, searchQuery]);

  // 2. Sort (preserves discovery order)
  const sortedResources = filtered;

  // Reset pagination to page 1 whenever search query or resources list changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, resources]);

  // 3. Pagination calculations
  const totalResources = sortedResources.length;
  const totalPages = Math.max(1, Math.ceil(totalResources / PAGE_SIZE));
  const safePage = Math.min(Math.max(1, currentPage), totalPages);

  const startIndex = (safePage - 1) * PAGE_SIZE;
  const endIndex = Math.min(startIndex + PAGE_SIZE, totalResources);
  const paginatedResources = sortedResources.slice(startIndex, endIndex);

  const rangeText =
    totalResources === 0
      ? ""
      : totalResources === 1
      ? "Showing 1 of 1 resource"
      : `Showing ${startIndex + 1}–${endIndex} of ${totalResources} resources`;

  const pageNumbers = getPageNumbers(safePage, totalPages);

  return (
    <div className="flex flex-col gap-4">
      {/* Search input */}
      <div className="relative">
        <svg
          className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none"
          xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
          stroke="currentColor" strokeWidth="2"
        >
          <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          id="search-input"
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search by name or ID…"
          className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-8 py-2 text-[13px] text-slate-300 placeholder-slate-600 focus:outline-none focus:border-slate-600 transition-colors"
        />
        {searchQuery.length > 0 && (
          <button
            onClick={() => setSearchQuery("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer text-sm leading-none"
            aria-label="Clear search"
          >
            ×
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto w-full">
        <table className="min-w-[580px] w-full text-sm text-left">
          <thead>
            <tr className="border-b border-slate-800/80">
              <th className="px-0 pb-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 pr-6">Name</th>
              <th className="px-0 pb-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 pr-6">Type</th>
              <th className="px-0 pb-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 pr-6">Status</th>
              <th className="px-0 pb-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 hidden sm:table-cell pr-6">Issues</th>
              <th className="px-0 pb-2.5 text-right text-[11px] font-semibold uppercase tracking-wider text-slate-500"></th>
            </tr>
          </thead>
          <tbody>
            {flatList.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-slate-600 text-sm">
                  No resources discovered in this scan.
                </td>
              </tr>
            ) : sortedResources.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-slate-600 text-sm">
                  No resources match "{searchQuery}".
                </td>
              </tr>
            ) : (
              paginatedResources.map((resource) => (
                <tr
                  key={resource.id}
                  className="border-b border-slate-800/40 hover:bg-slate-800/20 transition-colors"
                >
                  <td className="py-3 pr-6 font-medium text-slate-200 max-w-[180px] truncate text-[13px]">
                    {resource.name}
                  </td>
                  <td className="py-3 pr-6 text-slate-500 text-[12px]">
                    {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                  </td>
                  <td className="py-3 pr-6">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${
                        STATUS_BADGE[resource.status] || STATUS_BADGE.HEALTHY
                      }`}
                    >
                      {resource.status}
                    </span>
                  </td>
                  <td className="py-3 pr-6 text-slate-500 hidden sm:table-cell text-[12px] tabular-nums">
                    {resource.issues?.length || 0}
                  </td>
                  <td className="py-3 text-right">
                    <button
                      onClick={() => onInspect(resource)}
                      className="text-[12px] text-blue-400 hover:text-blue-300 transition-colors cursor-pointer bg-transparent border-none p-0"
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

      {/* Pagination & Counter footer */}
      {totalResources > 0 && (
        <nav aria-label="Resource table pagination" className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2">
          <p className="text-[12px] text-slate-500">
            {rangeText}
          </p>

          {totalPages > 1 && (
            <div className="flex items-center gap-1.5 self-start sm:self-auto flex-wrap">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={safePage === 1}
                aria-label="Go to previous page"
                className="px-2.5 py-1 text-[12px] border border-slate-800 rounded bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-slate-400 disabled:hover:border-slate-800 cursor-pointer"
              >
                ‹ Previous
              </button>

              <div className="flex items-center gap-1">
                {pageNumbers.map((p, idx) =>
                  p === "..." ? (
                    <span key={`ellipsis-${idx}`} className="px-1.5 py-0.5 text-[12px] text-slate-600 select-none">
                      …
                    </span>
                  ) : (
                    <button
                      key={p}
                      onClick={() => setCurrentPage(p)}
                      aria-label={`Go to page ${p}`}
                      aria-current={safePage === p ? "page" : undefined}
                      className={`min-w-[28px] h-7 px-2 text-[12px] rounded border transition-colors cursor-pointer ${
                        safePage === p
                          ? "bg-slate-800 border-slate-700 text-white font-medium"
                          : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                      }`}
                    >
                      {p}
                    </button>
                  )
                )}
              </div>

              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={safePage === totalPages}
                aria-label="Go to next page"
                className="px-2.5 py-1 text-[12px] border border-slate-800 rounded bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-slate-400 disabled:hover:border-slate-800 cursor-pointer"
              >
                Next ›
              </button>
            </div>
          )}
        </nav>
      )}
    </div>
  );
}
