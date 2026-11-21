import { useState, useMemo, useEffect } from "react";
import {
  RESOURCE_SERVICE_MAP,
  RESOURCE_TYPE_LABELS,
  STATUS_BADGE,
  CATEGORY_BADGE,
} from "../utils/constants";

const PAGE_SIZE = 15;

const SEVERITY_RANK = {
  CRITICAL: 1,
  WARNING: 2,
  ORPHANED: 3,
  NOT_ASSESSED: 4,
  HEALTHY: 5,
};

function getDisplayedStatus(resource) {
  if (resource?.status === "HEALTHY" && resource?.assessment?.status !== "ASSESSED") {
    return "NOT_ASSESSED";
  }
  return resource?.status || "NOT_ASSESSED";
}

function hasCostOrUnusedFinding(resource) {
  if (resource?.status === "ORPHANED") return true;
  return (resource?.issues || []).some(
    (i) => i?.category === "Cost Risk" || i?.category === "Unused" || i?.severity === "ORPHANED"
  );
}

function getPageNumbers(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "...", total];
  if (current >= total - 3) return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "...", current - 1, current, current + 1, "...", total];
}

export default function ResourceTable({
  resources = [],
  onInspect,
  initialStatusFilter = "ALL",
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [serviceFilter, setServiceFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState(initialStatusFilter);
  const [sortBy, setSortBy] = useState("severity");
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    setStatusFilter(initialStatusFilter);
  }, [initialStatusFilter]);

  // Compute service distribution from discovered resources
  const serviceCounts = useMemo(() => {
    const counts = new Map();
    for (const r of resources) {
      const svc = RESOURCE_SERVICE_MAP[r.type] || "Other";
      counts.set(svc, (counts.get(svc) || 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [resources]);

  // Compute status filter counts
  const statusCounts = useMemo(() => {
    let critical = 0;
    let warning = 0;
    let costUnused = 0;
    let healthy = 0;
    let notAssessed = 0;
    for (const r of resources) {
      const st = getDisplayedStatus(r);
      if (st === "CRITICAL") critical++;
      else if (st === "WARNING") warning++;
      else if (st === "HEALTHY") healthy++;
      else if (st === "NOT_ASSESSED") notAssessed++;
      if (hasCostOrUnusedFinding(r)) costUnused++;
    }
    return {
      all: resources.length,
      critical,
      warning,
      costUnused,
      healthy,
      notAssessed,
    };
  }, [resources]);

  // 1. Filter by search, service, and status
  const filtered = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    return resources.filter((r) => {
      if (serviceFilter !== "ALL") {
        const svc = RESOURCE_SERVICE_MAP[r.type] || "Other";
        if (svc !== serviceFilter) return false;
      }

      const st = getDisplayedStatus(r);
      if (statusFilter === "CRITICAL" && st !== "CRITICAL") return false;
      if (statusFilter === "WARNING" && st !== "WARNING") return false;
      if (statusFilter === "COST_UNUSED" && !hasCostOrUnusedFinding(r)) return false;
      if (statusFilter === "HEALTHY" && st !== "HEALTHY") return false;
      if (statusFilter === "NOT_ASSESSED" && st !== "NOT_ASSESSED") return false;

      if (!query) return true;

      const label = (RESOURCE_TYPE_LABELS[r.type] || r.type || "").toLowerCase();
      const service = (RESOURCE_SERVICE_MAP[r.type] || "").toLowerCase();
      const region = (r.region || "").toLowerCase();
      const issueText = (r.issues || [])
        .map((i) => `${i.rule_id || ""} ${i.title || ""} ${i.category || ""}`)
        .join(" ")
        .toLowerCase();

      return (
        (r.name || "").toLowerCase().includes(query) ||
        (r.id || "").toLowerCase().includes(query) ||
        label.includes(query) ||
        service.includes(query) ||
        region.includes(query) ||
        issueText.includes(query)
      );
    });
  }, [resources, searchQuery, serviceFilter, statusFilter]);

  // 2. Sort
  const sortedResources = useMemo(() => {
    const copy = [...filtered];
    if (sortBy === "severity") {
      copy.sort((a, b) => {
        const rankDiff =
          (SEVERITY_RANK[getDisplayedStatus(a)] || 99) -
          (SEVERITY_RANK[getDisplayedStatus(b)] || 99);
        if (rankDiff !== 0) return rankDiff;
        const issueDiff = (b.issues?.length || 0) - (a.issues?.length || 0);
        if (issueDiff !== 0) return issueDiff;
        return (a.name || "").localeCompare(b.name || "");
      });
    } else if (sortBy === "name") {
      copy.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    } else if (sortBy === "service") {
      copy.sort((a, b) => {
        const svcA = RESOURCE_SERVICE_MAP[a.type] || "";
        const svcB = RESOURCE_SERVICE_MAP[b.type] || "";
        return svcA.localeCompare(svcB) || (a.name || "").localeCompare(b.name || "");
      });
    }
    return copy;
  }, [filtered, sortBy]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, serviceFilter, statusFilter, sortBy, resources]);

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
  const hasActiveFilters = searchQuery.trim() !== "" || serviceFilter !== "ALL" || statusFilter !== "ALL";

  return (
    <div className="flex flex-col gap-4">
      {/* Service Inventory Filter Strip */}
      {serviceCounts.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            type="button"
            onClick={() => setServiceFilter("ALL")}
            className={`text-[11px] font-medium px-2.5 py-1 rounded-lg border transition-colors cursor-pointer ${
              serviceFilter === "ALL"
                ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
                : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
            }`}
          >
            All Services <span className="font-mono ml-1 opacity-75">{resources.length}</span>
          </button>
          {serviceCounts.map(([svc, count]) => (
            <button
              type="button"
              key={svc}
              onClick={() => setServiceFilter((prev) => (prev === svc ? "ALL" : svc))}
              className={`text-[11px] font-medium px-2.5 py-1 rounded-lg border transition-colors cursor-pointer ${
                serviceFilter === svc
                  ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
                  : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
              }`}
            >
              {svc} <span className="font-mono ml-1 opacity-75">{count}</span>
            </button>
          ))}
        </div>
      )}

      {/* Search + Sort Row */}
      <div className="flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1">
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
            placeholder="Search by name, ID, service, rule (e.g. ssh, nat, unencrypted, s3)…"
            className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-8 py-2 text-[13px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500/50 transition-colors"
          />
          {searchQuery.length > 0 && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer text-sm leading-none"
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>

        <select
          aria-label="Sort resources"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-teal-500/50 cursor-pointer"
        >
          <option value="severity">Sort: Highest Risk First</option>
          <option value="name">Sort: Name (A–Z)</option>
          <option value="service">Sort: AWS Service</option>
        </select>
      </div>

      {/* Status & Focus Filter Pills */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {[
            { key: "ALL", label: "All", count: statusCounts.all },
            { key: "CRITICAL", label: "Critical", count: statusCounts.critical, active: "bg-red-500/15 border-red-500/30 text-red-400" },
            { key: "WARNING", label: "Warning", count: statusCounts.warning, active: "bg-amber-500/15 border-amber-500/30 text-amber-400" },
            { key: "COST_UNUSED", label: "Unused & Cost Risk", count: statusCounts.costUnused, active: "bg-sky-500/15 border-sky-500/30 text-sky-300" },
            { key: "HEALTHY", label: "Healthy", count: statusCounts.healthy, active: "bg-emerald-500/15 border-emerald-500/30 text-emerald-400" },
            ...(statusCounts.notAssessed > 0
              ? [{ key: "NOT_ASSESSED", label: "Not Assessed", count: statusCounts.notAssessed, active: "bg-slate-700/40 border-slate-600 text-slate-300" }]
              : []),
          ].map((pill) => (
            <button
              type="button"
              key={pill.key}
              onClick={() => setStatusFilter(pill.key)}
              className={`text-[11px] font-medium px-2.5 py-1 rounded-md border transition-colors cursor-pointer ${
                statusFilter === pill.key
                  ? pill.active || "bg-slate-800 border-slate-600 text-white"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900"
              }`}
            >
              {pill.label} <span className="font-mono opacity-75 ml-0.5">{pill.count}</span>
            </button>
          ))}
        </div>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={() => {
              setSearchQuery("");
              setServiceFilter("ALL");
              setStatusFilter("ALL");
            }}
            className="text-[11px] text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0"
          >
            Reset filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto w-full rounded-xl border border-slate-800/80 bg-slate-900/30">
        <table className="min-w-[640px] w-full text-sm text-left">
          <thead>
            <tr className="border-b border-slate-800/80 bg-slate-900/60">
              <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Resource</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Type</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Status</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 hidden md:table-cell">Key Finding</th>
              <th className="px-4 py-2.5 text-right text-[11px] font-semibold uppercase tracking-wider text-slate-500"></th>
            </tr>
          </thead>
          <tbody>
            {resources.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-slate-500 text-sm">
                  No resources discovered in this scan.
                </td>
              </tr>
            ) : sortedResources.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-slate-500 text-sm">
                  No resources match the current search or filter.
                </td>
              </tr>
            ) : (
              paginatedResources.map((resource) => {
                const status = getDisplayedStatus(resource);
                const issues = resource.issues || [];
                const topIssue = issues[0];

                return (
                  <tr
                    key={`${resource.type}-${resource.id}-${resource.region}`}
                    onClick={() => onInspect(resource)}
                    className="border-b border-slate-800/40 last:border-b-0 hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 max-w-[220px]">
                      <p className="font-medium text-slate-200 truncate text-[13px]">{resource.name}</p>
                      <p className="text-[11px] font-mono text-slate-500 truncate mt-0.5">
                        {resource.id}
                        {resource.region ? ` · ${resource.region}` : ""}
                      </p>
                    </td>
                    <td className="px-3 py-3 text-slate-400 text-[12px] whitespace-nowrap">
                      {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          STATUS_BADGE[status] || STATUS_BADGE.NOT_ASSESSED
                        }`}
                      >
                        {status}
                      </span>
                    </td>
                    <td className="px-3 py-3 hidden md:table-cell max-w-[260px]">
                      {topIssue ? (
                        <div className="flex items-center gap-1.5 min-w-0">
                          {topIssue.category && (
                            <span className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                              CATEGORY_BADGE[topIssue.category] || "bg-slate-800 text-slate-400 border-slate-700"
                            }`}>
                              {topIssue.category}
                            </span>
                          )}
                          <span className="text-xs text-slate-300 truncate">{topIssue.title}</span>
                          {issues.length > 1 && (
                            <span className="text-[10px] font-mono text-slate-500 shrink-0">
                              +{issues.length - 1}
                            </span>
                          )}
                        </div>
                      ) : status === "NOT_ASSESSED" ? (
                        <span className="text-xs text-slate-500">Incomplete check evidence</span>
                      ) : (
                        <span className="text-xs text-emerald-500/80">All checks passed</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onInspect(resource);
                        }}
                        className="text-xs text-teal-400 hover:text-teal-300 font-medium transition-colors cursor-pointer bg-transparent border-none p-0"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {totalResources > 0 && (
        <nav aria-label="Resource table pagination" className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-1">
          <p className="text-[12px] text-slate-500">{rangeText}</p>

          {totalPages > 1 && (
            <div className="flex items-center gap-1.5 self-start sm:self-auto flex-wrap">
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={safePage === 1}
                aria-label="Go to previous page"
                className="px-2.5 py-1 text-[12px] border border-slate-800 rounded bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
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
                      type="button"
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
                type="button"
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={safePage === totalPages}
                aria-label="Go to next page"
                className="px-2.5 py-1 text-[12px] border border-slate-800 rounded bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
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
