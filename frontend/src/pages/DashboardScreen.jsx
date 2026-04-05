import { useState, useMemo, useRef } from "react";
import TopBar from "../components/TopBar";
import SummaryCards from "../components/SummaryCards";
import ResourceTable from "../components/ResourceTable";
import DetailDrawer from "../components/DetailDrawer";
import { RESOURCE_TYPE_LABELS, STATUS_BADGE } from "../utils/constants";

export default function DashboardScreen({ scanResults, onRescan }) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [expandedGroups, setExpandedGroups] = useState(new Set());
  const tableRef = useRef(null);

  const allResources = useMemo(() => {
    const results = scanResults;
    return [
      ...(results.resources.ec2_instances || []),
      ...(results.resources.s3_buckets || []),
      ...(results.resources.rds_instances || []),
      ...(results.resources.ebs_volumes || []),
      ...(results.resources.elastic_ips || []),
      ...(results.resources.security_groups || []),
      ...(results.resources.snapshots || []),
      ...(results.resources.iam_roles || []),
      ...(results.resources.lambda_functions || []),
      ...(results.resources.nat_gateways || []),
      ...(results.resources.load_balancers || []),
      ...(results.resources.dynamodb_tables || []),
      ...(results.resources.vpcs || []),
      ...(results.resources.auto_scaling_groups || []),
      ...(results.resources.ecs_clusters || []),
      ...(results.resources.eks_clusters || []),
      ...(results.resources.elasticache_clusters || []),
      ...(results.resources.sqs_queues || []),
      ...(results.resources.sns_topics || []),
      ...(results.resources.secrets || []),
      ...(results.resources.api_gateways || []),
      ...(results.resources.aurora_clusters || []),
      ...(results.resources.cloudformation_stacks || []),
      ...(results.resources.eventbridge_rules || []),
      ...(results.resources.ecr_repositories || []),
      ...(results.resources.internet_gateways || []),
      ...(results.resources.cloudwatch_alarms || []),
      ...(results.resources.redshift_clusters || []),
    ];
  }, [scanResults]);

  // Group resources by type
  const groupedResources = useMemo(() => {
    const groups = {};
    for (const resource of allResources) {
      if (!groups[resource.type]) groups[resource.type] = [];
      groups[resource.type].push(resource);
    }
    return groups;
  }, [allResources]);

  const getGroupStatus = (resources) => {
    if (resources.some(r => r.status === "CRITICAL")) return "CRITICAL";
    if (resources.some(r => r.status === "WARNING")) return "WARNING";
    if (resources.some(r => r.status === "ORPHANED")) return "ORPHANED";
    return "HEALTHY";
  };

  const STATUS_ORDER = { CRITICAL: 0, WARNING: 1, ORPHANED: 2, HEALTHY: 3 };
  const sortedGroupEntries = Object.entries(groupedResources).sort(([typeA, resA], [typeB, resB]) =>
    STATUS_ORDER[getGroupStatus(resA)] - STATUS_ORDER[getGroupStatus(resB)]
  );

  const toggleGroup = (type) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      next.has(type) ? next.delete(type) : next.add(type);
      return next;
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <TopBar
          accountId={scanResults.account_id}
          region={scanResults.region}
          scannedAt={scanResults.scanned_at}
          onRescan={onRescan}
        />

        {scanResults.partial === true && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border bg-amber-500/15 border-amber-500/30">
            <svg className="w-5 h-5 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
            <p className="text-sm text-amber-400">
              Scan completed partially due to timeout. Some resources may not be shown.
            </p>
          </div>
        )}

        <SummaryCards summary={scanResults.summary} />

        {/* Resource Type Summary Groups */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {sortedGroupEntries.map(([type, resources]) => {
            const groupStatus = getGroupStatus(resources);
            const totalIssues = resources.reduce((sum, r) => sum + r.issues.length, 0);
            const isExpanded = expandedGroups.has(type);
            const isDimmed = groupStatus === "HEALTHY" && totalIssues === 0;

            return (
              <div
                key={type}
                className={`bg-slate-800/60 border border-slate-700/50 rounded-xl backdrop-blur-sm transition-all ${isDimmed ? "opacity-60" : ""}`}
              >
                {/* Group Header */}
                <button
                  onClick={() => toggleGroup(type)}
                  className="w-full flex items-center gap-3 p-3 text-left cursor-pointer hover:bg-slate-700/20 transition-colors rounded-xl"
                >
                  <span className="text-slate-400 text-xs w-4 shrink-0">
                    {isExpanded ? "▼" : "▶"}
                  </span>
                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-medium text-slate-200 truncate block">
                      {RESOURCE_TYPE_LABELS[type] || type}
                    </span>
                  </div>
                  <span
                    className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold border ${STATUS_BADGE[groupStatus]}`}
                  >
                    {groupStatus}
                  </span>
                  <span className="text-xs text-slate-400 bg-slate-700/60 px-2 py-0.5 rounded-full">
                    {resources.length}
                  </span>
                </button>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="px-3 pb-3 border-t border-slate-700/30">
                    <ul className="mt-2 space-y-1.5">
                      {resources.slice(0, 5).map((r) => (
                        <li key={r.id} className="flex items-center gap-2 text-xs">
                          <span className="text-slate-300 truncate flex-1">{r.name}</span>
                          <span
                            className={`inline-block px-1.5 py-0.5 rounded-full text-[10px] font-semibold border ${STATUS_BADGE[r.status]}`}
                          >
                            {r.status}
                          </span>
                          {r.issues.length > 0 && (
                            <span className="text-slate-500 text-[10px]">
                              {r.issues.length} issue{r.issues.length !== 1 ? "s" : ""}
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                    <button
                      onClick={() => {
                        setTypeFilter(type);
                        tableRef.current?.scrollIntoView({ behavior: "smooth" });
                      }}
                      className="mt-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    >
                      View all in table →
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div ref={tableRef}>
          <ResourceTable
            resources={allResources}
            onInspect={(resource) => setSelectedResource(resource)}
            accountId={scanResults.account_id}
            typeFilter={typeFilter}
            onTypeFilterChange={(val) => setTypeFilter(val)}
          />
        </div>
      </div>

      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
