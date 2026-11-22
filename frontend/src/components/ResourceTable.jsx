import { useState, useMemo, useEffect } from "react";
import {
  CATEGORY_BADGE,
  RESOURCE_SERVICE_MAP,
  RESOURCE_TYPE_LABELS,
  STATUS_BADGE,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import { normalizeCategory } from "../utils/securityScore";

const PAGE_SIZE = 6;

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
  initialServiceFilter = "ALL",
  initialCategoryFilter = "ALL",
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [serviceFilter, setServiceFilter] = useState(initialServiceFilter);
  const [regionFilter, setRegionFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState(initialStatusFilter);
  const [categoryFilter, setCategoryFilter] = useState(initialCategoryFilter);
  const [sortBy, setSortBy] = useState("severity");
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    setStatusFilter(initialStatusFilter);
  }, [initialStatusFilter]);

  useEffect(() => {
    setServiceFilter(initialServiceFilter);
  }, [initialServiceFilter]);

  useEffect(() => {
    setCategoryFilter(initialCategoryFilter);
  }, [initialCategoryFilter]);

  // Live resource counts across all 10 supported services
  const serviceCounts = useMemo(() => {
    const counts = Object.fromEntries(SUPPORTED_SERVICES.map((s) => [s, 0]));
    for (const r of resources) {
      const svc = r.service || RESOURCE_SERVICE_MAP[r.type] || "Other";
      counts[svc] = (counts[svc] || 0) + 1;
    }
    return SUPPORTED_SERVICES.map((svc) => [svc, counts[svc] || 0]);
  }, [resources]);

  // Distinct regions present in the discovered inventory
  const discoveredRegions = useMemo(() => {
    const set = new Set();
    for (const r of resources) {
      if (r.region) set.add(r.region);
    }
    return Array.from(set).sort();
  }, [resources]);

  // Status filter counts
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
    return {
      all: resources.length,
      critical,
      warning,
      costUnused,
      info,
      healthy,
      incomplete,
    };
  }, [resources]);

  // 1. Filter by service, region, status, category, and multi-field search
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

      if (categoryFilter !== "ALL") {
        const hasCat = (r.issues || []).some(
          (i) => normalizeCategory(i?.category, i?.severity) === categoryFilter
        );
        if (!hasCat) return false;
      }

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
  }, [resources, searchQuery, serviceFilter, regionFilter, statusFilter, categoryFilter]);

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
  }, [searchQuery, serviceFilter, regionFilter, statusFilter, categoryFilter, sortBy, resources]);

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
  const hasActiveFilters =
    searchQuery.trim() !== "" ||
    serviceFilter !== "ALL" ||
    regionFilter !== "ALL" ||
    statusFilter !== "ALL" ||
    categoryFilter !== "ALL";

  return (
    <div className="flex flex-col gap-4">
      {/* 10 Supported Services Navigation Bar (horizontal rail on phones, wrapped pills on sm+) */}
      <div className="flex items-center gap-1.5 overflow-x-auto sm:overflow-visible sm:flex-wrap pb-1 sm:pb-0 -mx-1 px-1 sm:mx-0 sm:px-0 no-scrollbar">
        <button
          type="button"
          onClick={() => setServiceFilter("ALL")}
          className={`shrink-0 text-[11px] font-medium px-2.5 py-1.5 sm:py-1 rounded-lg border transition-colors cursor-pointer whitespace-nowrap ${
            serviceFilter === "ALL"
              ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
              : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
          }`}
        >
          All 10 Services <span className="font-mono ml-1 opacity-75">{resources.length}</span>
        </button>
        {serviceCounts.map(([svc, count]) => (
          <button
            type="button"
            key={svc}
            onClick={() => setServiceFilter((prev) => (prev === svc ? "ALL" : svc))}
            className={`shrink-0 text-[11px] font-medium px-2.5 py-1.5 sm:py-1 rounded-lg border transition-colors cursor-pointer whitespace-nowrap ${
              serviceFilter === svc
                ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
                : count === 0
                ? "bg-slate-950/40 border-slate-800/60 text-slate-600 hover:text-slate-400"
                : "bg-slate-900/60 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700"
            }`}
          >
            {svc} <span className="font-mono ml-1 opacity-75">{count}</span>
          </button>
        ))}
      </div>

      {/* Search + Region Filter + Sort Row */}
      <div className="flex flex-col lg:flex-row gap-2.5">
        <div className="relative flex-1 min-w-0">
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
            placeholder="Search by name, AWS ID, service, region, or finding…"
            className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-8 py-2.5 sm:py-2 text-base sm:text-[13px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500/50 transition-colors"
          />
          {searchQuery.length > 0 && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer text-base leading-none p-1"
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:flex gap-2 shrink-0">
          <select
            aria-label="Filter by region"
            value={regionFilter}
            onChange={(e) => setRegionFilter(e.target.value)}
            className="w-full lg:w-auto min-w-0 bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2.5 sm:py-2 text-xs text-slate-300 focus:outline-none focus:border-teal-500/50 cursor-pointer"
          >
            <option value="ALL">All Regions ({discoveredRegions.length})</option>
            {discoveredRegions.map((reg) => (
              <option key={reg} value={reg}>{reg}</option>
            ))}
          </select>

          <select
            aria-label="Sort resources"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="w-full lg:w-auto min-w-0 bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2.5 sm:py-2 text-xs text-slate-300 focus:outline-none focus:border-teal-500/50 cursor-pointer"
          >
            <option value="severity">Sort: Highest Risk First</option>
            <option value="service">Sort: AWS Service</option>
            <option value="region">Sort: Region</option>
            <option value="name">Sort: Name (A–Z)</option>
          </select>
        </div>
      </div>

      {/* Status & Category Focus Pills */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 overflow-x-auto sm:overflow-visible sm:flex-wrap pb-1 sm:pb-0 -mx-1 px-1 sm:mx-0 sm:px-0 no-scrollbar max-w-full">
          {[
            { key: "ALL", label: "All", count: statusCounts.all },
            { key: "CRITICAL", label: "Critical", count: statusCounts.critical, active: "bg-red-500/15 border-red-500/30 text-red-400" },
            { key: "WARNING", label: "Warning", count: statusCounts.warning, active: "bg-amber-500/15 border-amber-500/30 text-amber-400" },
            { key: "COST_UNUSED", label: "Potential Cost Waste", count: statusCounts.costUnused, active: "bg-sky-500/15 border-sky-500/30 text-sky-300" },
            ...(statusCounts.info > 0
              ? [{ key: "INFO", label: "Review Info", count: statusCounts.info, active: "bg-slate-600/20 border-slate-500/40 text-slate-200" }]
              : []),
            { key: "HEALTHY", label: "Healthy", count: statusCounts.healthy, active: "bg-emerald-500/15 border-emerald-500/30 text-emerald-400" },
            ...(statusCounts.incomplete > 0
              ? [{ key: "INCOMPLETE", label: "Check Incomplete", count: statusCounts.incomplete, active: "bg-orange-500/15 border-orange-500/30 text-orange-300" }]
              : []),
          ].map((pill) => (
            <button
              type="button"
              key={pill.key}
              onClick={() => setStatusFilter(pill.key)}
              className={`shrink-0 whitespace-nowrap text-[11px] font-medium px-2.5 py-1.5 sm:py-1 rounded-md border transition-colors cursor-pointer ${
                statusFilter === pill.key
                  ? pill.active || "bg-slate-800 border-slate-600 text-white"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900"
              }`}
            >
              {pill.label} <span className="font-mono opacity-75 ml-0.5">{pill.count}</span>
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          {categoryFilter !== "ALL" && (
            <button
              type="button"
              onClick={() => setCategoryFilter("ALL")}
              className="text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-200 hover:text-white cursor-pointer"
            >
              Category: {categoryFilter} ×
            </button>
          )}
          {hasActiveFilters && (
            <button
              type="button"
              onClick={() => {
                setSearchQuery("");
                setServiceFilter("ALL");
                setRegionFilter("ALL");
                setStatusFilter("ALL");
                setCategoryFilter("ALL");
              }}
              className="text-[11px] text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0 shrink-0"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>

      {/* Mobile Resource Card View (< md: zero horizontal scroll, touch-friendly) */}
      <div className="block md:hidden space-y-2.5">
        {resources.length === 0 ? (
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/30 py-10 px-4 text-center text-slate-500 text-sm">
            No resources discovered across the 10 supported AWS services.
          </div>
        ) : sortedResources.length === 0 ? (
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/30 py-10 px-4 text-center text-slate-500 text-sm">
            No resources match the current search or filter.
          </div>
        ) : (
          paginatedResources.map((resource) => {
            const status = getDisplayedStatus(resource);
            const issues = resource.issues || [];
            const topIssue = issues[0];
            const svc = resource.service || RESOURCE_SERVICE_MAP[resource.type] || "";

            return (
              <button
                type="button"
                key={`${resource.type}-${resource.id}-${resource.region}`}
                onClick={() => onInspect(resource)}
                className="w-full text-left rounded-xl border border-slate-800/80 bg-slate-900/40 hover:bg-slate-800/40 active:bg-slate-800/60 p-3.5 space-y-2.5 transition-colors cursor-pointer"
              >
                <div className="flex items-start justify-between gap-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-slate-100 text-[13px] truncate">{resource.name}</p>
                    <p className="text-[11px] font-mono text-slate-500 truncate mt-0.5">{resource.id}</p>
                  </div>
                  <span
                    className={`shrink-0 inline-block px-2 py-0.5 rounded text-[10px] font-semibold border ${
                      STATUS_BADGE[status] || STATUS_BADGE.INCOMPLETE
                    }`}
                  >
                    {status}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-400">
                  <span className="font-semibold text-slate-300">{svc}</span>
                  <span className="text-slate-700">·</span>
                  <span>{RESOURCE_TYPE_LABELS[resource.type] || resource.type}</span>
                  <span className="text-slate-700">·</span>
                  <span className="font-mono text-slate-400">{resource.region || "global"}</span>
                </div>

                <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/60">
                  <div className="min-w-0 flex-1">
                    {topIssue ? (
                      <div className="flex items-center gap-1.5 min-w-0">
                        {topIssue.category && (
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                              CATEGORY_BADGE[topIssue.category] || "bg-slate-800 text-slate-400 border-slate-700"
                            }`}
                          >
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
                    ) : status === "INCOMPLETE" ? (
                      <span className="text-xs text-orange-300/80">Check blocked by API / IAM error</span>
                    ) : (
                      <span className="text-xs text-emerald-500/80">All applicable checks passed</span>
                    )}
                  </div>
                  <span className="text-xs text-teal-400 font-medium shrink-0">Inspect →</span>
                </div>
              </button>
            );
          })
        )}
      </div>

      {/* Tablet & Desktop Resource Table (>= md) */}
      <div className="hidden md:block overflow-x-auto w-full rounded-xl border border-slate-800/80 bg-slate-900/30">
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="border-b border-slate-800/80 bg-slate-900/60">
              <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Resource</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Service / Type</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Region</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Health</th>
              <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 hidden lg:table-cell">Key Finding</th>
              <th className="px-4 py-2.5 text-right text-[11px] font-semibold uppercase tracking-wider text-slate-500"></th>
            </tr>
          </thead>
          <tbody>
            {resources.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500 text-sm">
                  No resources discovered across the 10 supported AWS services.
                </td>
              </tr>
            ) : sortedResources.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500 text-sm">
                  No resources match the current search or filter.
                </td>
              </tr>
            ) : (
              paginatedResources.map((resource) => {
                const status = getDisplayedStatus(resource);
                const issues = resource.issues || [];
                const topIssue = issues[0];
                const svc = resource.service || RESOURCE_SERVICE_MAP[resource.type] || "";

                return (
                  <tr
                    key={`${resource.type}-${resource.id}-${resource.region}`}
                    onClick={() => onInspect(resource)}
                    className="border-b border-slate-800/40 last:border-b-0 hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 max-w-[240px]">
                      <p className="font-medium text-slate-200 truncate text-[13px]">{resource.name}</p>
                      <p className="text-[11px] font-mono text-slate-500 truncate mt-0.5">{resource.id}</p>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <p className="text-xs font-medium text-slate-300">{svc}</p>
                      <p className="text-[11px] text-slate-500">
                        {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                      </p>
                    </td>
                    <td className="px-3 py-3 text-[11px] font-mono text-slate-400 whitespace-nowrap">
                      {resource.region || "global"}
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          STATUS_BADGE[status] || STATUS_BADGE.INCOMPLETE
                        }`}
                      >
                        {status}
                      </span>
                    </td>
                    <td className="px-3 py-3 hidden lg:table-cell max-w-[280px]">
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
                      ) : status === "INCOMPLETE" ? (
                        <span className="text-xs text-orange-300/80">Check blocked by API / IAM error</span>
                      ) : (
                        <span className="text-xs text-emerald-500/80">All applicable checks passed</span>
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

      {/* Pagination */}
      {totalResources > 0 && (
        <nav aria-label="Resource table pagination" className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-1">
          <p className="text-[12px] text-slate-500">{rangeText}</p>
          {totalPages > 1 && (
            <div className="flex items-center justify-between sm:justify-end gap-1.5 w-full sm:w-auto flex-wrap">
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={safePage === 1}
                className="min-h-[34px] sm:min-h-[28px] px-3 sm:px-2.5 py-1 text-[12px] border border-slate-800 rounded-md bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 cursor-pointer"
              >
                ‹ Prev
              </button>
              <div className="flex items-center gap-1 flex-wrap justify-center">
                {pageNumbers.map((p, idx) =>
                  p === "..." ? (
                    <span key={`ellipsis-${idx}`} className="px-1 py-0.5 text-[12px] text-slate-600 select-none">…</span>
                  ) : (
                    <button
                      type="button"
                      key={p}
                      onClick={() => setCurrentPage(p)}
                      aria-current={safePage === p ? "page" : undefined}
                      className={`min-w-[32px] sm:min-w-[28px] h-8 sm:h-7 px-2 text-[12px] rounded-md border transition-colors cursor-pointer ${
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
                className="min-h-[34px] sm:min-h-[28px] px-3 sm:px-2.5 py-1 text-[12px] border border-slate-800 rounded-md bg-slate-900/50 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-40 cursor-pointer"
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
