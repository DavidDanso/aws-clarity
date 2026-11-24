import { useState, useMemo, useEffect } from "react";
import {
  RESOURCE_SERVICE_MAP,
  RESOURCE_TYPE_LABELS,
  STATUS_BADGE,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import { normalizeCategory } from "../utils/securityScore";

const PAGE_SIZE = 15;

const SEVERITY_RANK = {
  CRITICAL: 1,
  WARNING: 2,
  UNUSED: 3,
  INCOMPLETE: 4,
  HEALTHY: 5,
};

function getDisplayedStatus(resource) {
  if (resource?.status === "HEALTHY" && resource?.assessment?.status !== "COMPLETE") {
    return "INCOMPLETE";
  }
  return resource?.status || "INCOMPLETE";
}

function hasCostOrUnusedFinding(resource) {
  if (resource?.status === "UNUSED") return true;
  return (resource?.issues || []).some(
    (i) => normalizeCategory(i?.category, i?.severity) === "Potential Cost Waste"
  );
}

function hasInfoObservation(resource) {
  return (resource?.issues || []).some((i) => i?.severity === "INFO");
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
  const [regionFilter, setRegionFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState(initialStatusFilter);
  const [sortBy, setSortBy] = useState("severity");
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    setStatusFilter(initialStatusFilter);
  }, [initialStatusFilter]);

  const serviceCounts = useMemo(() => {
    const counts = Object.fromEntries(SUPPORTED_SERVICES.map((s) => [s, 0]));
    for (const r of resources) {
      const svc = r.service || RESOURCE_SERVICE_MAP[r.type] || "Other";
      counts[svc] = (counts[svc] || 0) + 1;
    }
    return SUPPORTED_SERVICES.map((svc) => [svc, counts[svc] || 0]);
  }, [resources]);

  const discoveredRegions = useMemo(() => {
    const set = new Set();
    for (const r of resources) {
      if (r.region) set.add(r.region);
    }
    return Array.from(set).sort();
  }, [resources]);

  const statusCounts = useMemo(() => {
    let critical = 0;
    let warning = 0;
    let costUnused = 0;
    let info = 0;
    let healthy = 0;
    let incomplete = 0;
    for (const r of resources) {
      const st = getDisplayedStatus(r);
      if (st === "CRITICAL") critical++;
      else if (st === "WARNING") warning++;
      else if (st === "HEALTHY") healthy++;
      else if (st === "INCOMPLETE") incomplete++;
      if (hasCostOrUnusedFinding(r)) costUnused++;
      if (hasInfoObservation(r)) info++;
    }
    return { all: resources.length, critical, warning, costUnused, info, healthy, incomplete };
  }, [resources]);

  const filtered = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    return resources.filter((r) => {
      const svc = r.service || RESOURCE_SERVICE_MAP[r.type] || "Other";
      if (serviceFilter !== "ALL" && svc !== serviceFilter) return false;
      if (regionFilter !== "ALL" && (r.region || "global") !== regionFilter) return false;

      const st = getDisplayedStatus(r);
      if (statusFilter === "CRITICAL" && st !== "CRITICAL") return false;
      if (statusFilter === "WARNING" && st !== "WARNING") return false;
      if (statusFilter === "COST_UNUSED" && !hasCostOrUnusedFinding(r)) return false;
      if (statusFilter === "INFO" && !hasInfoObservation(r)) return false;
      if (statusFilter === "HEALTHY" && st !== "HEALTHY") return false;
      if (statusFilter === "INCOMPLETE" && st !== "INCOMPLETE") return false;

      if (!query) return true;

      const label = (RESOURCE_TYPE_LABELS[r.type] || r.type || "").toLowerCase();
      const region = (r.region || "").toLowerCase();
      const issueText = (r.issues || [])
        .map((i) => `${i.rule_id || ""} ${i.title || ""} ${i.category || ""}`)
        .join(" ")
        .toLowerCase();

      return (
        (r.name || "").toLowerCase().includes(query) ||
        (r.id || "").toLowerCase().includes(query) ||
        label.includes(query) ||
        svc.toLowerCase().includes(query) ||
        region.includes(query) ||
        issueText.includes(query)
      );
    });
  }, [resources, searchQuery, serviceFilter, regionFilter, statusFilter]);

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
        const svcA = a.service || RESOURCE_SERVICE_MAP[a.type] || "";
        const svcB = b.service || RESOURCE_SERVICE_MAP[b.type] || "";
        return svcA.localeCompare(svcB) || (a.name || "").localeCompare(b.name || "");
      });
    } else if (sortBy === "region") {
      copy.sort((a, b) => (a.region || "").localeCompare(b.region || "") || (a.name || "").localeCompare(b.name || ""));
    }
    return copy;
  }, [filtered, sortBy]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, serviceFilter, regionFilter, statusFilter, sortBy, resources]);

  const totalResources = sortedResources.length;
  const totalPages = Math.max(1, Math.ceil(totalResources / PAGE_SIZE));
  const safePage = Math.min(Math.max(1, currentPage), totalPages);
  const startIndex = (safePage - 1) * PAGE_SIZE;
  const endIndex = Math.min(startIndex + PAGE_SIZE, totalResources);
  const paginatedResources = sortedResources.slice(startIndex, endIndex);

  const rangeText =
    totalResources === 0
      ? ""
      : `Showing ${startIndex + 1}–${endIndex} of ${totalResources}`;

  const pageNumbers = getPageNumbers(safePage, totalPages);
  const hasActiveFilters =
    searchQuery.trim() !== "" ||
    serviceFilter !== "ALL" ||
    regionFilter !== "ALL" ||
    statusFilter !== "ALL";

  return (
    <div className="space-y-3">
      {/* Single Compact Filter & Search Toolbar */}
      <div className="flex flex-col lg:flex-row gap-2">
        <div className="relative flex-1 min-w-0">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            id="search-input"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by name, ID, service, region, or finding…"
            className="w-full bg-slate-900/70 border border-slate-800 rounded-xl pl-9 pr-8 py-2 text-sm sm:text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500/60 transition-colors"
          />
          {searchQuery.length > 0 && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-200 cursor-pointer bg-transparent border-0 p-1 text-sm"
            >
              ×
            </button>
          )}
        </div>

        <div className="grid grid-cols-2 sm:flex items-center gap-2 shrink-0">
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-teal-500/60 cursor-pointer"
          >
            <option value="ALL">All Statuses ({statusCounts.all})</option>
            <option value="CRITICAL">Critical ({statusCounts.critical})</option>
            <option value="WARNING">Warning ({statusCounts.warning})</option>
            <option value="COST_UNUSED">Cost / Review ({statusCounts.costUnused})</option>
            {statusCounts.info > 0 && <option value="INFO">Info Notes ({statusCounts.info})</option>}
            <option value="HEALTHY">Healthy ({statusCounts.healthy})</option>
            {statusCounts.incomplete > 0 && <option value="INCOMPLETE">Incomplete ({statusCounts.incomplete})</option>}
          </select>

          <select
            aria-label="Filter by AWS service"
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-teal-500/60 cursor-pointer"
          >
            <option value="ALL">All Services</option>
            {serviceCounts.map(([svc, count]) => (
              <option key={svc} value={svc}>
                {svc} ({count})
              </option>
            ))}
          </select>

          {discoveredRegions.length > 1 && (
            <select
              aria-label="Filter by region"
              value={regionFilter}
              onChange={(e) => setRegionFilter(e.target.value)}
              className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-teal-500/60 cursor-pointer"
            >
              <option value="ALL">All Regions ({discoveredRegions.length})</option>
              {discoveredRegions.map((reg) => (
                <option key={reg} value={reg}>
                  {reg}
                </option>
              ))}
            </select>
          )}

          <select
            aria-label="Sort resources"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-teal-500/60 cursor-pointer"
          >
            <option value="severity">Highest Risk First</option>
            <option value="service">Service (A–Z)</option>
            <option value="region">Region (A–Z)</option>
            <option value="name">Name (A–Z)</option>
          </select>
        </div>
      </div>

      {/* Active Filter Indicator (only shown when filtered) */}
      {hasActiveFilters && (
        <div className="flex items-center justify-between gap-2 text-xs text-slate-400 px-1">
          <span>
            Showing <strong className="text-slate-200">{totalResources}</strong> matching resource{totalResources === 1 ? "" : "s"}
          </span>
          <button
            type="button"
            onClick={() => {
              setSearchQuery("");
              setServiceFilter("ALL");
              setRegionFilter("ALL");
              setStatusFilter("ALL");
            }}
            className="text-teal-400 hover:text-teal-300 font-medium bg-transparent border-0 p-0 cursor-pointer"
          >
            Clear filters
          </button>
        </div>
      )}

      {/* Single Semantic Responsive Table (stacks via @container on narrow screens) */}
      <div
        tabIndex={0}
        role="region"
        aria-labelledby="inventory-table-caption"
        className="clarity-table-wrapper rounded-2xl border border-slate-800/80 bg-slate-900/35 focus:outline-none focus-visible:ring-1 focus-visible:ring-teal-500/60"
      >
        <table className="clarity-table text-left text-sm">
          <caption id="inventory-table-caption" className="sr-only">
            Discovered AWS resources across supported services
          </caption>
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/95">
              <th scope="col" className="px-4 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Resource
              </th>
              <th scope="col" className="px-3 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Service
              </th>
              <th scope="col" className="px-3 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Region
              </th>
              <th scope="col" className="px-3 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Status
              </th>
              <th scope="col" className="px-3 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Finding
              </th>
              <th scope="col" className="px-4 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <span className="sr-only">Action</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {resources.length === 0 ? (
              <tr data-empty="true">
                <td colSpan={6} className="py-12 px-4 text-center text-slate-500 text-sm">
                  No resources discovered across the scanned AWS services.
                </td>
              </tr>
            ) : sortedResources.length === 0 ? (
              <tr data-empty="true">
                <td colSpan={6} className="py-12 px-4 text-center text-slate-500 text-sm">
                  No resources match your current filters.
                </td>
              </tr>
            ) : (
              paginatedResources.map((resource) => {
                const status = getDisplayedStatus(resource);
                const issues = resource.issues || [];
                const topIssue = issues[0];
                const svc = resource.service || RESOURCE_SERVICE_MAP[resource.type] || "";
                const typeLabel = RESOURCE_TYPE_LABELS[resource.type] || resource.type;

                return (
                  <tr
                    key={`${resource.type}-${resource.id}-${resource.region}`}
                    onClick={() => onInspect(resource)}
                    className="border-b border-slate-800/45 last:border-b-0 hover:bg-slate-800/35 transition-colors cursor-pointer"
                  >
                    <th scope="row" className="px-4 py-3 font-normal text-left max-w-[240px]">
                      <p className="font-medium text-slate-100 truncate text-[13px]">{resource.name}</p>
                      <p className="text-[11px] font-mono text-slate-500 truncate mt-0.5">{resource.id}</p>
                    </th>
                    <td data-label="Service" className="px-3 py-3 whitespace-nowrap">
                      <span className="text-xs text-slate-200 font-medium">{svc}</span>
                      <span className="text-[11px] text-slate-500 block">{typeLabel}</span>
                    </td>
                    <td data-label="Region" className="px-3 py-3 text-xs font-mono text-slate-400 whitespace-nowrap">
                      {resource.region || "global"}
                    </td>
                    <td data-label="Status" className="px-3 py-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded-md text-[10px] font-semibold border ${
                          STATUS_BADGE[status] || STATUS_BADGE.INCOMPLETE
                        }`}
                      >
                        {status}
                      </span>
                    </td>
                    <td data-label="Finding" className="px-3 py-3 max-w-[280px]">
                      {topIssue ? (
                        <span className="text-xs text-slate-300 truncate block">
                          {topIssue.title}
                          {issues.length > 1 && (
                            <span className="text-[11px] font-mono text-slate-500 ml-1.5">
                              +{issues.length - 1}
                            </span>
                          )}
                        </span>
                      ) : status === "INCOMPLETE" ? (
                        <span className="text-xs text-orange-300/80">Check incomplete</span>
                      ) : (
                        <span className="text-xs text-slate-500">All checks passed</span>
                      )}
                    </td>
                    <td data-action="true" className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onInspect(resource);
                        }}
                        className="text-xs text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-0 p-0"
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

      {/* Clean Pagination */}
      {totalResources > 0 && (
        <nav aria-label="Resource pagination" className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 pt-1">
          <p className="text-xs text-slate-500">{rangeText}</p>
          {totalPages > 1 && (
            <div className="flex items-center gap-1 flex-wrap">
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={safePage === 1}
                className="px-2.5 py-1 text-xs border border-slate-800 rounded-lg bg-slate-900/60 text-slate-300 hover:text-white hover:border-slate-700 disabled:opacity-35 cursor-pointer"
              >
                ‹ Prev
              </button>
              {pageNumbers.map((p, idx) =>
                p === "..." ? (
                  <span key={`ellipsis-${idx}`} className="px-1 text-xs text-slate-600">
                    …
                  </span>
                ) : (
                  <button
                    type="button"
                    key={p}
                    onClick={() => setCurrentPage(p)}
                    aria-current={safePage === p ? "page" : undefined}
                    className={`min-w-[28px] h-7 px-2 text-xs rounded-lg border transition-colors cursor-pointer ${
                      safePage === p
                        ? "bg-slate-800 border-slate-600 text-white font-semibold"
                        : "border-transparent text-slate-400 hover:text-white hover:bg-slate-900"
                    }`}
                  >
                    {p}
                  </button>
                )
              )}
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={safePage === totalPages}
                className="px-2.5 py-1 text-xs border border-slate-800 rounded-lg bg-slate-900/60 text-slate-300 hover:text-white hover:border-slate-700 disabled:opacity-35 cursor-pointer"
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
