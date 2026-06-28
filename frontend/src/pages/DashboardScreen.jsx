import { useState, useMemo } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import { RESOURCE_TYPE_LABELS } from "../utils/constants";

function getResourceCost(r) {
  switch (r.type) {
    case "ec2_instance":
      if (r.raw?.state === "stopped") return 0;
      return 8.47;
    case "s3_bucket":
      if (r.raw?.is_empty) return 0;
      return 1.15;
    case "lambda_function":
      if (r.raw?.invocations === 0 || r.raw?.invoked === false) return 0;
      return 0.005; // tiny value for sorting/math, display as "< $0.01"
    case "dynamodb_table":
      return 1.25;
    case "api_gateway":
      return 3.50;
    case "rds_instance":
    case "elasticache_cluster":
    case "cloudfront_distribution":
    case "ebs_volume":
    case "nat_gateway":
      return null;
    case "elastic_ip":
      // Only show if unattached
      if (r.raw?.association_id) return 0;
      return null;
    default:
      return 0;
  }
}

function renderCost(cost, type) {
  if (type === "lambda_function") {
    return "< $0.01";
  }
  if (cost === null || cost === undefined) {
    return "—";
  }
  return `$${cost.toFixed(2)} / mo`;
}

export default function DashboardScreen({ scanResults, onRescan, isLoading, scanStatus, scanError }) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [healthyExpanded, setHealthyExpanded] = useState(false);

  const allResources = useMemo(() => {
    const results = scanResults;
    if (!results || !results.resources) return [];
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

  // Step 1: Section 1 — resources with at least one issue
  const securityResources = useMemo(() => {
    return allResources.filter((r) => r.status && r.status !== "HEALTHY");
  }, [allResources]);

  const s1Ids = useMemo(() => new Set(securityResources.map((r) => r.id)), [securityResources]);

  const sortedSecurityResources = useMemo(() => {
    const severityPriority = {
      CRITICAL: 1,
      WARNING: 2,
      ORPHANED: 3,
    };
    return [...securityResources].sort((a, b) => {
      return (severityPriority[a.status] || 99) - (severityPriority[b.status] || 99);
    });
  }, [securityResources]);

  const hasIssues = sortedSecurityResources.length > 0;

  // Step 2: Section 2 — billable resources not already in S1
  const BILLABLE_TYPES = [
    "ec2_instance",
    "s3_bucket",
    "lambda_function",
    "dynamodb_table",
    "api_gateway",
    "rds_instance",
    "elasticache_cluster",
    "cloudfront_distribution",
    "ebs_volume",
    "nat_gateway",
    "elastic_ip",
  ];

  const costResources = useMemo(() => {
    return allResources.filter((r) => {
      if (s1Ids.has(r.id)) return false;
      if (!BILLABLE_TYPES.includes(r.type)) return false;
      const cost = getResourceCost(r);
      return cost !== null && cost > 0;
    });
  }, [allResources, s1Ids]);

  const s2Ids = useMemo(() => new Set(costResources.map((r) => r.id)), [costResources]);

  const sortedCostResources = useMemo(() => {
    return [...costResources].sort((a, b) => {
      const costA = getResourceCost(a) ?? -1;
      const costB = getResourceCost(b) ?? -1;
      return costB - costA;
    });
  }, [costResources]);

  const maxCost = useMemo(() => {
    return Math.max(...costResources.map((r) => getResourceCost(r) || 0), 0);
  }, [costResources]);

  const totalCost = useMemo(() => {
    return costResources.reduce((sum, r) => {
      const cost = getResourceCost(r);
      // Lambda has tiny dummy cost internally, treat as 0 for display sum
      if (r.type === "lambda_function") return sum + 0;
      return sum + (cost || 0);
    }, 0);
  }, [costResources]);

  // Step 3: Section 3 — everything not in S1 or S2
  const healthyFreeResources = useMemo(() => {
    return allResources.filter((r) => !s1Ids.has(r.id) && !s2Ids.has(r.id));
  }, [allResources, s1Ids, s2Ids]);

  const handleExportCSV = () => {
    const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
    const headers = ["Name", "ID", "Type", "Status", "Issues Count", "Issues Detail"];
    const rows = allResources.map(r => [
      escape(r.name),
      escape(r.id),
      escape(RESOURCE_TYPE_LABELS[r.type] || r.type),
      escape(r.status),
      escape(r.issues?.length || 0),
      escape(r.issues && r.issues.length > 0 ? r.issues.map(i => i.message).join("; ") : "None"),
    ].join(","));
    const csvString = [headers.map(escape).join(","), ...rows].join("\n");
    const date = new Date().toISOString().slice(0, 10);
    const filename = `aws-clarity-scan-${scanResults.account_id || "account"}-${date}.csv`;
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
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="max-w-7xl mx-auto px-4 py-6 flex flex-col gap-[40px]">
        <TopBar
          accountId={scanResults?.account_id || ""}
          region={scanResults?.region || ""}
          scannedAt={scanResults?.scanned_at || ""}
          onRescan={onRescan}
          isLoading={isLoading}
        />

        {scanResults?.partial === true && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border border-slate-700/50">
            <svg className="w-5 h-5 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
            <p className="text-sm text-slate-400">
              Scan completed partially due to timeout. Some resources may not be shown.
            </p>
          </div>
        )}

        {/* Security posture section */}
        <section className="flex flex-col gap-4">
          {isLoading ? (
            <div className="animate-pulse bg-slate-800 h-[22px] w-36 rounded" />
          ) : scanError ? null : (
            <h2 className="text-[15px] font-medium text-slate-200">
              {hasIssues ? "Needs attention" : "All clear"}
            </h2>
          )}
          {scanError ? (
            <p className="text-[13px] text-slate-400 py-1">
              Scan failed —{" "}
              <a
                href="javascript:void(0)"
                onClick={() => onRescan()}
                className="text-blue-400 hover:text-blue-300"
              >
                retry
              </a>
            </p>
          ) : isLoading ? (
            <div className="flex flex-col w-full text-slate-400 py-2">
              Scanning... Status: {scanStatus}
            </div>
          ) : hasIssues ? (
            <div className="flex flex-col w-full">
              {sortedSecurityResources.map((resource) => (
                <div
                  key={resource.id}
                  className={`flex items-center w-full h-[44px] border-b-[0.5px] border-slate-800/80 bg-transparent px-3 border-l-4 ${
                    resource.status === "CRITICAL"
                      ? "border-l-red-500"
                      : resource.status === "WARNING"
                      ? "border-l-amber-500"
                      : "border-l-slate-500"
                  }`}
                >
                  <div className="flex items-baseline gap-2 shrink-0">
                    <span className="text-[14px] font-medium text-slate-200">{resource.name}</span>
                    <span className="text-[12px] text-slate-500 font-normal">
                      {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                    </span>
                  </div>
                  <div className="text-[13px] text-slate-400 ml-4 truncate flex-1 min-w-0">
                    {resource.issues && resource.issues.length > 0
                      ? resource.issues.map((i) => i.message).join(", ")
                      : "No issues"}
                  </div>
                  <button
                    onClick={() => setSelectedResource(resource)}
                    className="text-[13px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer ml-4 shrink-0"
                  >
                    Inspect →
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-[13px] py-1">
              <svg className="w-[16px] h-[16px] text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-slate-400 font-normal">Security posture clean — no issues detected</span>
            </div>
          )}
        </section>

        {/* Cost intelligence / Active spend section */}
        <section className="flex flex-col gap-4">
          <div>
            <h2 className="text-[15px] font-medium text-slate-200">Active spend</h2>
            <p className="text-[13px] text-slate-400 mt-1">Resources incurring real AWS charges</p>
          </div>
          {scanError ? (
            <p className="text-[13px] text-slate-400 py-1">
              Scan failed —{" "}
              <a
                href="javascript:void(0)"
                onClick={() => onRescan()}
                className="text-blue-400 hover:text-blue-300"
              >
                retry
              </a>
            </p>
          ) : isLoading ? (
            <div className="flex flex-col w-full">
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className="flex items-center justify-between w-full h-[40px] border-b-[0.5px] border-slate-800/80 bg-transparent px-3"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="animate-pulse bg-slate-800 h-3.5 w-20 rounded" />
                    <div className="animate-pulse bg-slate-900 h-4 w-12 rounded-full" />
                  </div>
                  <div className="flex-1 mx-4 max-w-[120px] h-[2px] bg-slate-900 rounded-full overflow-hidden shrink-0" />
                  <div className="animate-pulse bg-slate-800 h-3.5 w-16 rounded" />
                </div>
              ))}
            </div>
          ) : sortedCostResources.length > 0 ? (
            <div className="flex flex-col w-full">
              {sortedCostResources.map((resource) => {
                const cost = getResourceCost(resource);
                const widthPercent = cost && maxCost > 0 ? (cost / maxCost) * 100 : 0;
                return (
                  <div
                    key={resource.id}
                    className="flex items-center justify-between w-full h-[40px] border-b-[0.5px] border-slate-800/80 bg-transparent px-3"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[14px] font-medium text-slate-200 truncate">{resource.name}</span>
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-normal bg-slate-800/80 border border-slate-700/50 text-slate-400 shrink-0">
                        {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                      </span>
                    </div>

                    {/* Proportional visual ranking signal bar */}
                    <div className="flex-1 mx-4 max-w-[120px] h-[2px] bg-slate-900 rounded-full overflow-hidden shrink-0">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${widthPercent}%`, backgroundColor: 'var(--color-border-primary, rgb(51 65 85))' }}
                      />
                    </div>

                    <div className="text-[14px] text-slate-300 font-medium font-mono shrink-0 text-right">
                      {renderCost(cost, resource.type)}
                    </div>
                  </div>
                );
              })}

              <div className="flex justify-end items-center gap-1.5 mt-4 text-[14px]">
                <span className="text-slate-500">Estimated monthly total</span>
                <span className="text-slate-200 font-medium font-mono">${totalCost.toFixed(2)}</span>
              </div>
            </div>
          ) : (
            <div className="text-[14px] text-slate-500 py-1">
              No active spend detected.
            </div>
          )}
        </section>

        {/* Healthy & free resources section */}
        <section className="flex flex-col gap-2">
          {scanError ? (
            <p className="text-[13px] text-slate-400 py-1">
              Scan failed —{" "}
              <a
                href="javascript:void(0)"
                onClick={() => onRescan()}
                className="text-blue-400 hover:text-blue-300"
              >
                retry
              </a>
            </p>
          ) : isLoading ? (
            <div className="animate-pulse bg-slate-800 h-5 w-72 rounded mt-2" />
          ) : (
            <>
              <button
                onClick={() => setHealthyExpanded(!healthyExpanded)}
                className="flex items-center text-[13px] text-slate-500 hover:text-slate-400 font-normal bg-transparent border-none p-0 cursor-pointer select-none text-left"
              >
                {healthyExpanded ? "↑" : "↓"} {healthyFreeResources.length} healthy resources with no issues and no cost
              </button>

              {healthyExpanded && (
                <div className="flex flex-col w-full gap-1.5 mt-2 max-w-xl text-[13px] text-slate-500">
                  {healthyFreeResources.map((resource) => (
                    <div key={resource.id} className="flex justify-between py-0.5">
                      <span className="text-slate-400 truncate pr-4">{resource.name}</span>
                      <span className="text-slate-600 shrink-0">
                        {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </section>

        {/* Footer */}
        {!scanError && scanResults && (
        <footer className="flex justify-center pt-4 border-t border-slate-900/60 mt-4">
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              handleExportCSV();
            }}
            className="text-[13px] text-slate-500 hover:text-slate-400 font-normal underline transition-colors cursor-pointer"
          >
            Export CSV
          </a>
        </footer>
        )}
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



