import { useState, useMemo } from "react";
import TopBar from "../components/TopBar";
import DetailDrawer from "../components/DetailDrawer";
import { RESOURCE_TYPE_LABELS } from "../utils/constants";
import { scanAccount } from "../services/api";

const AWS_SERVICE_LABELS = {
  "Amazon Elastic Compute Cloud - Compute": "EC2 Instances",
  "Amazon EC2 - Other": "EBS / Network",
  "Amazon Simple Storage Service": "S3 Storage",
  "Amazon Relational Database Service": "RDS Databases",
  "Amazon Aurora MySQL": "Aurora MySQL",
  "Amazon Aurora PostgreSQL": "Aurora PostgreSQL",
  "AWS Lambda": "Lambda Functions",
  "Amazon DynamoDB": "DynamoDB",
  "Amazon Virtual Private Cloud": "VPC / Networking",
  "Amazon API Gateway": "API Gateway",
  "AWS Secrets Manager": "Secrets Manager",
  "Amazon ElastiCache": "ElastiCache",
  "Amazon Elastic Container Service": "ECS",
  "Amazon Elastic Kubernetes Service": "EKS",
  "Amazon Redshift": "Redshift",
  "Amazon Simple Queue Service": "SQS",
  "Amazon Simple Notification Service": "SNS",
  "Amazon CloudWatch": "CloudWatch",
  "AWS CloudFormation": "CloudFormation",
  "Amazon Elastic Container Registry": "ECR",
  "Amazon EventBridge": "EventBridge",
  "AWS Key Management Service": "KMS",
  "Amazon Route 53": "Route 53",
  "Amazon CloudFront": "CloudFront",
};

const formatCost = (amount) => {
  if (amount === null || amount === undefined) return "—";
  if (amount < 0.01) return "< $0.01";
  if (amount >= 1000) return `$${(amount / 1000).toFixed(2)}k`;
  return `$${amount.toFixed(2)}`;
};

export default function DashboardScreen({
  scanResults,
  onRescan,
  isLoading,
  scanStatus,
  scanError,
  storedRoleArn,
  storedRegions,
  onStoredRegionsChange,
  onResultsChange,
}) {
  const [selectedResource, setSelectedResource] = useState(null);
  const [healthyExpanded, setHealthyExpanded] = useState(false);
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanError, setRescanError] = useState(null);

  const handleRegionChange = async (newRegions) => {
    if (!storedRoleArn || newRegions.length === 0) return;
    setIsRescanning(true);
    setRescanError(null);
    try {
      const newResults = await scanAccount(storedRoleArn, newRegions);
      onResultsChange(newResults);
      onStoredRegionsChange(newRegions);
    } catch (err) {
      setRescanError(err.message || "Failed to switch regions. Please try again.");
    } finally {
      setIsRescanning(false);
    }
  };

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

  const costData = scanResults?.costs ?? {};
  const costError = costData.error ?? null;
  const byService = costData.by_service ?? {};
  const totalCurrentMonth = costData.total_current_month ?? 0;
  const costPeriod = costData.period ?? {};
  const resourceLevelEnabled = costData.resource_level_enabled ?? false;

  const sortedServiceCosts = Object.entries(byService)
    .filter(([, amount]) => amount > 0)
    .sort(([, a], [, b]) => b - a);

  const maxServiceCost = sortedServiceCosts.length > 0
    ? sortedServiceCosts[0][1]
    : 1;

  // Step 3: Section 3 — healthy resources without security issues
  const healthyFreeResources = useMemo(() => {
    return allResources.filter((r) => !s1Ids.has(r.id));
  }, [allResources, s1Ids]);

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
      <div className="px-4 sm:px-6 lg:px-8 py-4 sm:py-6 max-w-7xl mx-auto w-full flex flex-col gap-[40px]">
        <TopBar
          accountId={scanResults?.account_id || ""}
          region={scanResults?.region || ""}
          scannedAt={scanResults?.scanned_at || ""}
          onRescan={onRescan}
          isLoading={isLoading}
          selectedRegions={storedRegions}
          onRegionChange={handleRegionChange}
          isRescanning={isRescanning}
        />

        {/* Scanning overlay */}
        {isRescanning && (
          <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
            <svg
              className="animate-spin w-6 h-6 text-teal-400"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-gray-200">Switching regions...</p>
              <p className="text-xs text-gray-400 mt-1">This usually takes 10–20 seconds.</p>
            </div>
          </div>
        )}

        {/* Error banner */}
        {rescanError && (
          <div className="mx-4 sm:mx-6 lg:mx-8 mt-2 px-4 py-3 rounded-lg bg-red-900/40 border border-red-700 text-sm text-red-300 flex items-center justify-between gap-3">
            <span>{rescanError}</span>
            <button
              onClick={() => setRescanError(null)}
              className="shrink-0 text-red-400 hover:text-red-200 text-lg leading-none"
            >
              ×
            </button>
          </div>
        )}

        <div className={isRescanning ? "pointer-events-none opacity-50 select-none" : ""}>

        {/* Empty state — shown when scan succeeded but region has zero resources */}
        {!isLoading && !scanError && scanResults && (scanResults.summary?.total_resources ?? 0) === 0 && (
          <div className="flex flex-col items-center justify-center gap-4 py-24 text-center px-4">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="48"
              height="48"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className="text-gray-600"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <div>
              <p className="text-base font-medium text-gray-300">No resources found</p>
              <p className="text-sm text-gray-500 mt-1">
                No active AWS resources were detected in{" "}
                {scanResults.regions?.length === 1
                  ? scanResults.regions[0]
                  : scanResults.regions?.length > 1
                  ? `${scanResults.regions.length} selected regions`
                  : "the selected region"}.
              </p>
              <p className="text-xs text-gray-600 mt-2">
                Try selecting a different region using the region selector above.
              </p>
            </div>
          </div>
        )}

        {/* Main dashboard — only renders when there are resources */}
        {(scanResults?.summary?.total_resources ?? 0) > 0 && (
        <>

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
            <div className="flex flex-col items-center justify-center gap-4 py-8 text-center">
              <svg
                className="animate-spin w-8 h-8 text-teal-400"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
              <div>
                <p className="text-sm font-medium text-gray-200">Scanning your AWS account...</p>
                <p className="text-xs text-gray-400 mt-1">
                  {storedRegions && storedRegions.length > 1
                    ? `Scanning ${storedRegions.length} regions simultaneously. This takes 15–30 seconds.`
                    : "This usually takes 10–20 seconds."}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  First scan may take a few extra seconds while the system warms up.
                </p>
              </div>
            </div>
          ) : hasIssues ? (
            <div className="flex flex-col w-full">
              {sortedSecurityResources.map((resource) => (
                <div
                  key={resource.id}
                  className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-2 py-3 w-full border-b-[0.5px] border-slate-800/80 bg-transparent px-3 border-l-4 ${
                    resource.status === "CRITICAL"
                      ? "border-l-red-500"
                      : resource.status === "WARNING"
                      ? "border-l-amber-500"
                      : "border-l-slate-500"
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 min-w-0">
                    <span className="text-[14px] font-medium text-slate-200 truncate max-w-[200px] sm:max-w-none">{resource.name}</span>
                    <span className="text-[12px] text-slate-500 font-normal shrink-0">
                      {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
                    </span>
                    <div className="text-[13px] text-slate-400 truncate min-w-0 sm:ml-2">
                      {resource.issues && resource.issues.length > 0
                        ? resource.issues.map((i) => i.message).join(", ")
                        : "No issues"}
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedResource(resource)}
                    className="text-[13px] text-blue-400 hover:text-blue-300 font-normal bg-transparent border-none p-0 cursor-pointer self-start sm:self-auto shrink-0"
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

        {/* Active spend section */}
        <div className="mt-6">

          {/* Section header */}
          <div className="flex items-center justify-between mb-2">
            <div>
              <h2 className="text-sm font-semibold text-gray-200">Active spend</h2>
              <p className="text-xs text-gray-500">
                {costError
                  ? "Cost data unavailable"
                  : costPeriod.start
                    ? `${costPeriod.start} to ${costPeriod.end} · real data · up to 24h delay`
                    : ""}
              </p>
            </div>
            {/* Resource-level badge */}
            {resourceLevelEnabled && (
              <span className="text-xs bg-teal-500/10 text-teal-400 border border-teal-500/20 rounded-full px-2.5 py-1">
                Per-resource costs available
              </span>
            )}
          </div>

          {/* PERMISSION DENIED — user needs to add ce:GetCostAndUsage */}
          {costError === "PERMISSION_DENIED" && (
            <div className="rounded-xl border border-amber-700/40 bg-amber-900/10 px-4 py-4">
              <p className="text-xs font-semibold text-amber-400 mb-1">Cost data requires one more permission</p>
              <p className="text-xs text-gray-400 mb-3">
                Add{" "}
                <code className="bg-gray-800 text-amber-400 px-1.5 py-0.5 rounded font-mono">
                  ce:GetCostAndUsage
                </code>{" "}
                to your <code className="bg-gray-800 text-teal-400 px-1.5 py-0.5 rounded font-mono">AWSClarityReadOnly</code> IAM role to enable real cost tracking.
              </p>
              <a
                href="https://console.aws.amazon.com/iam/home#/roles/AWSClarityReadOnly"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors"
              >
                Update IAM role in AWS Console →
              </a>
            </div>
          )}

          {/* OTHER ERROR */}
          {costError && costError !== "PERMISSION_DENIED" && (
            <div className="rounded-xl border border-gray-700 bg-gray-800/40 px-4 py-3">
              <p className="text-xs text-gray-400">Cost data could not be retrieved for this scan.</p>
            </div>
          )}

          {/* FREE TIER / ZERO SPEND — real $0, not missing data */}
          {!costError && sortedServiceCosts.length === 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900/40 px-4 py-4 text-center">
              <p className="text-sm text-gray-300 font-medium">$0.00 this month</p>
              <p className="text-xs text-gray-500 mt-1">
                No billable spend detected. Your account may be within AWS Free Tier.
              </p>
            </div>
          )}

          {/* REAL COST DATA */}
          {!costError && sortedServiceCosts.length > 0 && (
            <div>
              {/* Per-resource availability notice */}
              {!resourceLevelEnabled && (
                <div className="mb-3 flex items-start gap-2 px-3 py-2.5 rounded-lg bg-gray-800/40 border border-gray-700/60">
                  <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-500 shrink-0 mt-0.5">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    Showing costs by AWS service. For cost per individual resource, enable{" "}
                    <a
                      href="https://console.aws.amazon.com/cost-management/home#/settings"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
                    >
                      Resource-level data
                    </a>{" "}
                    in Cost Explorer settings (costs $0.01/resource/day).
                  </p>
                </div>
              )}

              {/* Cost rows */}
              <div className="space-y-0">
                {sortedServiceCosts.map(([serviceName, amount]) => {
                  const label = AWS_SERVICE_LABELS[serviceName] || serviceName;
                  const barPct = Math.max(4, Math.round((amount / maxServiceCost) * 100));
                  return (
                    <div
                      key={serviceName}
                      className="flex items-center gap-3 py-2.5 border-b border-gray-800/60 last:border-b-0"
                    >
                      <span className="text-sm text-gray-200 min-w-0 flex-1 truncate">{label}</span>
                      <div className="w-28 h-1 bg-gray-800 rounded-full shrink-0 hidden sm:block">
                        <div
                          className="h-1 bg-teal-500/50 rounded-full transition-all"
                          style={{ width: `${barPct}%` }}
                        />
                      </div>
                      <span className="text-sm font-mono text-gray-100 shrink-0 w-24 text-right">
                        {formatCost(amount)}
                        <span className="text-xs text-gray-500 font-sans"> / mo</span>
                      </span>
                    </div>
                  );
                })}
              </div>

              {/* Monthly total */}
              <div className="flex justify-end items-baseline gap-2 pt-3 border-t border-gray-800 mt-1">
                <span className="text-xs text-gray-500">Estimated monthly total</span>
                <span className="text-lg font-semibold text-white">{formatCost(totalCurrentMonth)}</span>
              </div>
            </div>
          )}

        </div>

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

        </>
        )}

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



