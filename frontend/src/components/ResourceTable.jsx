import { useState, useMemo } from "react";

const STATUS_BADGE = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  WARNING: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  HEALTHY: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  ORPHANED: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const RESOURCE_TYPE_LABELS = {
  ec2_instance: "EC2 Instance",
  s3_bucket: "S3 Bucket",
  rds_instance: "RDS Instance",
  ebs_volume: "EBS Volume",
  elastic_ip: "Elastic IP",
  security_group: "Security Group",
  snapshot: "EBS Snapshot",
  iam_role: "IAM Role",
  lambda_function: "Lambda Function",
  nat_gateway: "NAT Gateway",
  load_balancer: "Load Balancer",
  dynamodb_table: "DynamoDB Table",
  vpc: "VPC",
  auto_scaling_group: "Auto Scaling Group",
  ecs_cluster: "ECS Cluster",
  eks_cluster: "EKS Cluster",
  elasticache_cluster: "ElastiCache Cluster",
  sqs_queue: "SQS Queue",
  sns_topic: "SNS Topic",
  secret: "Secrets Manager",
  api_gateway: "API Gateway",
  aurora_cluster: "Aurora Cluster",
  cloudformation_stack: "CloudFormation Stack",
  eventbridge_rule: "EventBridge Rule",
  ecr_repository: "ECR Repository",
  internet_gateway: "Internet Gateway",
  cloudwatch_alarm: "CloudWatch Alarm",
  redshift_cluster: "Redshift Cluster",
};

export default function ResourceTable({ resources, onInspect }) {
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // resources is now a pre-flattened array from DashboardScreen
  const flatList = resources;

  // Get unique types and statuses for filter dropdowns
  const uniqueTypes = useMemo(() => [...new Set(flatList.map((r) => r.type))], [flatList]);
  const uniqueStatuses = useMemo(() => [...new Set(flatList.map((r) => r.status))], [flatList]);

  // Apply filters
  const filtered = useMemo(() => {
    return flatList.filter((r) => {
      if (typeFilter !== "ALL" && r.type !== typeFilter) return false;
      if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
      return true;
    });
  }, [flatList, typeFilter, statusFilter]);

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl backdrop-blur-sm overflow-hidden">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 p-4 border-b border-slate-700/50">
        <span className="text-sm text-slate-400 font-medium">Filters:</span>
        <select
          id="type-filter"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
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
        <span className="text-xs text-slate-500 ml-auto">
          {filtered.length} of {flatList.length} resources
        </span>
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
  );
}
