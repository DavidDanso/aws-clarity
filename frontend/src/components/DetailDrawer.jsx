import { useState, useEffect, useRef } from "react";

// ── Severity styles ────────────────────────────────────────────────────────────
const SEVERITY_STYLE = {
  CRITICAL: {
    badge:  "text-red-400 bg-red-500/10 border border-red-500/20",
    border: "border-red-500/30",
    left:   "border-l-red-500",
  },
  WARNING: {
    badge:  "text-amber-400 bg-amber-500/10 border border-amber-500/20",
    border: "border-amber-500/30",
    left:   "border-l-amber-500",
  },
  ORPHANED: {
    badge:  "text-slate-400 bg-slate-500/10 border border-slate-500/20",
    border: "border-slate-500/30",
    left:   "border-l-slate-500",
  },
};

const STATUS_COLOR = {
  CRITICAL: "text-red-400",
  WARNING:  "text-amber-400",
  HEALTHY:  "text-emerald-400",
  ORPHANED: "text-slate-400",
};

// Fallback metadata for rules in case of legacy/mock finding objects
const RULE_EXPLANATIONS = {
  "S3-001": {
    what_found: "Bucket contains 0 objects and has no active storage usage.",
    what_checked: "Queried S3 bucket object count and storage usage.",
  },
  "S3-002": {
    what_found: "Bucket policy explicitly allows public read or write access from the internet.",
    what_checked: "Queried S3 GetBucketPolicyStatus API to evaluate policy public access.",
  },
  "S3-003": {
    what_found: "Bucket Access Control List (ACL) grants permissions to AllUsers or AuthenticatedUsers.",
    what_checked: "Queried S3 GetBucketAcl API and inspected grantee URI definitions.",
  },
  "S3-004": {
    what_found: "Server-side encryption is not enabled by default for objects stored in this bucket.",
    what_checked: "Queried S3 GetBucketEncryption API configuration.",
  },
  "S3-005": {
    what_found: "One or more of the four S3 Block Public Access controls are disabled.",
    what_checked: "Queried S3 GetPublicAccessBlock configuration for all 4 security flags.",
  },
  "SG-001": {
    what_found: "Inbound firewall rule allows all protocols (-1) and all ports from 0.0.0.0/0 or ::/0.",
    what_checked: "Evaluated Security Group ingress IP permissions for unrestricted CIDR routes across all protocols.",
  },
  "SG-002": {
    what_found: "Inbound SSH access is allowed from 0.0.0.0/0 or ::/0 on port 22.",
    what_checked: "Evaluated Security Group ingress IP permissions for port 22 with unrestricted CIDR sources.",
  },
  "SG-003": {
    what_found: "Inbound RDP access is allowed from 0.0.0.0/0 or ::/0 on port 3389.",
    what_checked: "Evaluated Security Group ingress IP permissions for port 3389 with unrestricted CIDR sources.",
  },
  "RDS-001": {
    what_found: "RDS instance PubliclyAccessible flag is set to true and placed in a public subnet.",
    what_checked: "Inspected RDS DescribeDBInstances PubliclyAccessible configuration.",
  },
  "RDS-002": {
    what_found: "RDS instance storage encryption is disabled.",
    what_checked: "Inspected RDS DescribeDBInstances StorageEncrypted attribute.",
  },
  "RDS-003": {
    what_found: "Deletion protection is disabled on this RDS instance.",
    what_checked: "Inspected RDS DescribeDBInstances DeletionProtection attribute.",
  },
  "EBS-001": {
    what_found: "EBS volume block storage has encryption disabled.",
    what_checked: "Inspected EC2 DescribeVolumes Encrypted attribute.",
  },
  "EBS-002": {
    what_found: "EBS volume is in 'available' state and not attached to any EC2 instance.",
    what_checked: "Inspected EC2 DescribeVolumes State and Attachments list.",
  },
  "IAM-001": {
    what_found: "Inline IAM policy statement contains Action: * or Action: iam:* with Effect: Allow.",
    what_checked: "Parsed IAM role inline policy documents for unrestricted Action: * statements.",
  },
  "IAM-002": {
    what_found: "IAM policy statements grant actions with Resource: * without resource scoping.",
    what_checked: "Parsed IAM role inline policy documents for statements with Resource: *.",
  },
  "IAM-003": {
    what_found: "AWS managed policy AdministratorAccess is attached to this IAM role.",
    what_checked: "Inspected IAM ListAttachedRolePolicies for AdministratorAccess.",
  },
  "IAM-004": {
    what_found: "AWS managed policy IAMFullAccess is attached to this IAM role.",
    what_checked: "Inspected IAM ListAttachedRolePolicies for IAMFullAccess.",
  },
  "IAM-005": {
    what_found: "Role trust policy allows Principal: * or AWS: * to assume the role.",
    what_checked: "Parsed AssumeRolePolicyDocument for wildcard Principal definitions.",
  },
  "IAM-006": {
    what_found: "IAM policy statement grants full wildcard actions across an entire service (e.g. s3:*, ec2:*).",
    what_checked: "Parsed IAM policy statements for actions ending with :* combined with Resource: *.",
  },
  "IAM-007": {
    what_found: "AWS managed policy PowerUserAccess is attached to this IAM role.",
    what_checked: "Inspected IAM ListAttachedRolePolicies for PowerUserAccess.",
  },
  "IAM-008": {
    what_found: "Cross-account trust relationship does not enforce an sts:ExternalId condition.",
    what_checked: "Inspected AssumeRolePolicyDocument cross-account principals for sts:ExternalId conditions.",
  },
  "EC2-001": {
    what_found: "EC2 instance is in 'stopped' state while retaining attached storage and IPs.",
    what_checked: "Inspected EC2 DescribeInstances instance state.",
  },
  "EIP-001": {
    what_found: "Elastic IP address has no active AssociationId or attached network interface.",
    what_checked: "Inspected EC2 DescribeAddresses association_id field.",
  },
  "SNAP-001": {
    what_found: "The EBS volume from which this snapshot was taken has been deleted or cannot be found.",
    what_checked: "Cross-referenced Snapshot VolumeId against active EBS volumes in the account.",
  },
};

// Keys to skip in the raw metadata section (shown via structured UI instead)
const RAW_SKIP_KEYS = [
  "tags", "security_groups", "attachments", "inline_policies", "attached_managed_policies",
  "trust_policy", "ebs_volumes", "iam_instance_profile", "role", "elastic_ip", "elastic_ips",
  "db_subnet_group_name", "public_ip", "private_ip", "subnet_ids"
];

function formatLastChecked(ts) {
  if (!ts) return "Not available";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short"
    });
  } catch {
    return String(ts);
  }
}

function normalizeIssue(issue) {
  if (typeof issue === "string") {
    return {
      rule_id: null,
      severity: "WARNING",
      title: issue,
      what_found: issue,
      why: "Unused or unmaintained cloud resources increase attack surface and unnecessary exposure.",
      what_checked: "Inspected resource configuration and activity timestamps.",
      evidence: null,
      fix: "Review whether this resource is still in active use. Terminate or archive if obsolete.",
    };
  }

  const ruleId = issue.rule_id || null;
  const fallback = ruleId ? RULE_EXPLANATIONS[ruleId] : null;

  return {
    rule_id: ruleId,
    severity: issue.severity || "WARNING",
    title: issue.title || issue.message || "Security finding detected",
    what_found: issue.what_found || fallback?.what_found || issue.description || issue.title || issue.message,
    why: issue.why || null,
    what_checked: issue.what_checked || fallback?.what_checked || (ruleId ? `Evaluated ${ruleId} security rule criteria.` : "Inspected AWS configuration."),
    evidence: issue.evidence && typeof issue.evidence === "object" && Object.keys(issue.evidence).length > 0 ? issue.evidence : null,
    fix: issue.fix || "Review resource configuration and align with AWS security best practices.",
    scanned_at: issue.scanned_at || null,
  };
}

export default function DetailDrawer({ resource, onClose, scannedAt, history, previousScannedAt }) {
  const drawerRef = useRef(null);
  const [rawExpanded, setRawExpanded] = useState(false);

  useEffect(() => {
    const handleClick = (e) => {
      if (drawerRef.current && !drawerRef.current.contains(e.target)) onClose();
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [onClose]);

  useEffect(() => {
    const handleKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose]);

  if (!resource) return null;

  const rawEntries = Object.entries(resource.raw || {}).filter(
    ([key]) => !RAW_SKIP_KEYS.includes(key)
  );

  // ── Related resources: extract from raw where scanner already stored them ────
  const relatedItems = [];
  const raw = resource.raw || {};

  if (raw.vpc_id) {
    relatedItems.push({ label: "VPC", value: raw.vpc_id, type: "network" });
  }
  if (raw.subnet_id) {
    relatedItems.push({ label: "Subnet", value: raw.subnet_id, type: "network" });
  }
  if (Array.isArray(raw.security_groups) && raw.security_groups.length > 0) {
    relatedItems.push({ label: "Security Groups", value: raw.security_groups.join(", "), type: "security" });
  }
  if (Array.isArray(raw.ebs_volumes) && raw.ebs_volumes.length > 0) {
    relatedItems.push({ label: "Attached EBS Volumes", value: raw.ebs_volumes.join(", "), type: "storage" });
  }
  if (Array.isArray(raw.attachments) && raw.attachments.length > 0) {
    const attached = raw.attachments.map(a => a.InstanceId || a.instance_id || JSON.stringify(a)).join(", ");
    relatedItems.push({ label: "Attached Instance", value: attached, type: "compute" });
  }
  if (raw.iam_instance_profile) {
    relatedItems.push({ label: "IAM Instance Profile", value: raw.iam_instance_profile, type: "iam" });
  }
  if (raw.role) {
    relatedItems.push({ label: "Execution IAM Role", value: raw.role, type: "iam" });
  }
  if (raw.elastic_ip) {
    relatedItems.push({ label: "Elastic IP", value: raw.elastic_ip, type: "network" });
  }
  if (raw.db_subnet_group_name) {
    relatedItems.push({ label: "DB Subnet Group", value: raw.db_subnet_group_name, type: "network" });
  }
  if (raw.public_ip) {
    relatedItems.push({ label: "Public IP", value: raw.public_ip, type: "network" });
  }
  if (raw.private_ip) {
    relatedItems.push({ label: "Private IP", value: raw.private_ip, type: "network" });
  }

  const resolvedScannedAt = resource.scanned_at || scannedAt;

  return (
    <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm">
      <div
        ref={drawerRef}
        className="absolute right-0 top-0 h-full w-full sm:w-[480px] md:w-[560px] bg-slate-900 border-l border-slate-700/50 shadow-2xl overflow-y-auto animate-slide-in"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 sm:p-6 border-b border-slate-700/50">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                {resource.type}
              </span>
              <span className={`text-[11px] font-bold px-2 py-0.5 rounded ${
                STATUS_COLOR[resource.status] || "text-slate-300"
              } bg-slate-800/80`}>
                {resource.status}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white truncate">{resource.name}</h2>
            <p className="text-xs text-slate-500 font-mono truncate mt-0.5">{resource.id}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-4 w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            aria-label="Close inspection drawer"
          >
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 sm:p-6 space-y-6">

          {/* Quick Context Strip */}
          <div className="flex items-center justify-between gap-4 text-xs text-slate-400 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-semibold">Region</span>
              <span className="font-mono text-slate-200">{resource.region || "Global"}</span>
            </div>
            <div className="text-right">
              <span className="text-slate-500 block text-[10px] uppercase font-semibold">Last Checked</span>
              <span className="font-mono text-slate-200">{formatLastChecked(resolvedScannedAt)}</span>
            </div>
          </div>

          {/* ── RESOURCE HISTORY & RECENT CHANGES ─────────────────────────── */}
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
              Resource History & Observed Changes
            </h3>

            {history && history.hasHistory ? (
              <div className="bg-slate-950/60 rounded-xl border border-slate-800/80 p-3.5 space-y-3">
                {/* Status lifecycle comparison */}
                <div className="grid grid-cols-2 gap-3 text-xs pb-3 border-b border-slate-800/60">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold mb-1">
                      Current Status
                    </span>
                    <div className="flex items-center gap-2">
                      <span className={`font-bold px-2 py-0.5 rounded text-[11px] bg-slate-800/80 ${STATUS_COLOR[history.currentStatus] || "text-slate-300"}`}>
                        {history.currentStatus}
                      </span>
                      <span className="text-slate-400 text-[11px] font-mono">
                        {formatLastChecked(resolvedScannedAt)}
                      </span>
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold mb-1">
                      Previous Scan Status
                    </span>
                    <div className="flex items-center gap-2">
                      {history.previousStatus ? (
                        <>
                          <span className={`font-bold px-2 py-0.5 rounded text-[11px] bg-slate-800/80 ${STATUS_COLOR[history.previousStatus] || "text-slate-300"}`}>
                            {history.previousStatus}
                          </span>
                          <span className="text-slate-400 text-[11px] font-mono">
                            {formatLastChecked(previousScannedAt)}
                          </span>
                        </>
                      ) : (
                        <span className="text-cyan-400 font-medium text-[11px] bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                          Newly Discovered
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Status Transition Alert if changed */}
                {history.statusChanged && history.previousStatus && (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-950/30 border border-indigo-500/20 text-xs">
                    <span className="text-indigo-400 font-bold shrink-0">🔄</span>
                    <span className="text-slate-300 font-medium">
                      Status transitioned from{" "}
                      <span className={STATUS_COLOR[history.previousStatus]}>{history.previousStatus}</span>
                      {" "}to{" "}
                      <span className={STATUS_COLOR[history.currentStatus]}>{history.currentStatus}</span>
                    </span>
                  </div>
                )}

                {/* Granular finding changes */}
                <div className="space-y-1.5 text-xs">
                  {history.isNew && (
                    <div className="flex items-center gap-2 py-1 px-2.5 rounded bg-cyan-950/20 text-cyan-300">
                      <span className="font-bold">⚡</span>
                      <span>Resource was first observed during the most recent scan.</span>
                    </div>
                  )}

                  {history.resolvedIssues?.length > 0 && (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider block">
                        Resolved Findings ({history.resolvedIssues.length})
                      </span>
                      {history.resolvedIssues.map((resIssue, idx) => (
                        <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-emerald-950/30 text-emerald-300">
                          <span className="font-bold shrink-0">✓</span>
                          {resIssue.ruleId && <span className="text-[10px] font-mono shrink-0">{resIssue.ruleId}</span>}
                          <span className="truncate">{resIssue.title}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {history.newIssues?.length > 0 && (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] font-bold uppercase text-cyan-400 tracking-wider block">
                        Newly Detected Findings ({history.newIssues.length})
                      </span>
                      {history.newIssues.map((newIssue, idx) => (
                        <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-cyan-950/30 text-cyan-300">
                          <span className="font-bold shrink-0">⚡</span>
                          {newIssue.ruleId && <span className="text-[10px] font-mono shrink-0">{newIssue.ruleId}</span>}
                          <span className="truncate">{newIssue.title}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {history.stillOpenIssues?.length > 0 && (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] font-bold uppercase text-amber-400 tracking-wider block">
                        Still Open Findings ({history.stillOpenIssues.length})
                      </span>
                      {history.stillOpenIssues.map((openIssue, idx) => (
                        <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-amber-950/30 text-amber-300">
                          <span className="font-bold shrink-0">⚠</span>
                          {openIssue.ruleId && <span className="text-[10px] font-mono shrink-0">{openIssue.ruleId}</span>}
                          <span className="truncate">{openIssue.title}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {!history.isNew &&
                   (!history.resolvedIssues || history.resolvedIssues.length === 0) &&
                   (!history.newIssues || history.newIssues.length === 0) &&
                   (!history.stillOpenIssues || history.stillOpenIssues.length === 0) && (
                    <p className="text-slate-500 italic py-1">
                      No security finding changes detected between the last two scans.
                    </p>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/40 rounded-xl border border-slate-800/60 p-3 text-xs text-slate-500 flex items-center gap-2.5">
                <span className="text-slate-400">ℹ</span>
                <span>
                  First scan for this resource session. Comparative history and observed changes will appear after subsequent scans.
                </span>
              </div>
            )}
          </div>

          {/* ── Findings Section — Progressive Disclosure ────────────────── */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200">
                Security Findings ({resource.issues?.length || 0})
              </h3>
              {resource.issues?.length > 0 && (
                <span className="text-[11px] text-slate-500">
                  Evidence-based verification
                </span>
              )}
            </div>

            {(!resource.issues || resource.issues.length === 0) ? (
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-4 flex items-center gap-3 text-sm text-emerald-400">
                <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                <div>
                  <p className="font-medium text-emerald-300">No issues detected</p>
                  <p className="text-xs text-emerald-500 mt-0.5">Configuration aligns with AWS security best practices.</p>
                </div>
              </div>
            ) : (
              <div className="space-y-5">
                {resource.issues.map((rawIssue, idx) => {
                  const issue = normalizeIssue(rawIssue);
                  const style = SEVERITY_STYLE[issue.severity] || SEVERITY_STYLE.WARNING;
                  const evidenceEntries = issue.evidence
                    ? Object.entries(issue.evidence)
                    : [];

                  return (
                    <div
                      key={idx}
                      className={`rounded-xl border ${style.border} border-l-4 ${style.left} bg-slate-900/90 overflow-hidden shadow-sm`}
                    >
                      {/* 1. Finding Header: Rule ID, Severity, Timestamp */}
                      <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800/60 flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2">
                          {issue.rule_id && (
                            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded shrink-0 ${style.badge}`}>
                              {issue.rule_id}
                            </span>
                          )}
                          <span className={`text-[11px] font-bold uppercase tracking-wider ${style.badge.split(" ")[0]}`}>
                            {issue.severity}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400 font-mono">
                          Checked: {formatLastChecked(issue.scanned_at || resolvedScannedAt)}
                        </span>
                      </div>

                      <div className="p-4 space-y-3.5 text-xs">
                        {/* Title */}
                        <h4 className="text-sm font-semibold text-slate-100 leading-snug">
                          {issue.title}
                        </h4>

                        {/* ── PROGRESSIVE DISCLOSURE: Stage 1 (Summary First) ── */}
                        {issue.what_found && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              What Was Found
                            </span>
                            <p className="text-slate-200 leading-relaxed bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/70">
                              {issue.what_found}
                            </p>
                          </div>
                        )}

                        {issue.why && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              Why It Matters
                            </span>
                            <p className="text-slate-300 leading-relaxed">
                              {issue.why}
                            </p>
                          </div>
                        )}

                        {/* ── PROGRESSIVE DISCLOSURE: Stage 2 (Evidence & Details Second) ── */}
                        {issue.what_checked && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              What Clarity Checked
                            </span>
                            <p className="text-slate-400 leading-relaxed">
                              {issue.what_checked}
                            </p>
                          </div>
                        )}

                        <div>
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                            Evidence Observed by Scanner
                          </span>
                          {evidenceEntries.length > 0 ? (
                            <div className="rounded-lg bg-slate-950 border border-slate-800/80 divide-y divide-slate-800/60 overflow-hidden font-mono text-[11px]">
                              {evidenceEntries.map(([k, v]) => (
                                <div key={k} className="flex items-baseline justify-between gap-3 px-3 py-1.5">
                                  <span className="text-slate-400 shrink-0">{k}:</span>
                                  <span className="text-slate-100 text-right break-all">
                                    {typeof v === "object" ? JSON.stringify(v) : String(v)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-slate-500 italic text-[11px]">
                              No specific evidence payload recorded by scanner.
                            </p>
                          )}
                        </div>

                        {/* ── PROGRESSIVE DISCLOSURE: Stage 3 (Remediation Third) ── */}
                        {issue.fix && (
                          <div className="pt-1">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-teal-400 block mb-1">
                              Recommended Action
                            </span>
                            <div className="p-3 rounded-lg bg-teal-950/20 border border-teal-500/20 text-teal-200 leading-relaxed text-[12px]">
                              {issue.fix}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* ── Related Resources ────────────────────────────────────────────── */}
          {relatedItems.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Related Resources</h3>
              <div className="bg-slate-950/60 rounded-lg border border-slate-800/80 divide-y divide-slate-800/60">
                {relatedItems.map(({ label, value }) => (
                  <div key={label} className="flex flex-col sm:flex-row sm:justify-between sm:gap-2 px-3.5 py-2 text-xs">
                    <span className="text-slate-400 shrink-0">{label}</span>
                    <span className="text-slate-200 sm:text-right font-mono break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Raw Technical Metadata (Collapsible) ─────────────────────────── */}
          {rawEntries.length > 0 && (
            <div className="border-t border-slate-800/80 pt-4">
              <button
                type="button"
                onClick={() => setRawExpanded(prev => !prev)}
                className="flex items-center justify-between w-full text-left text-xs font-semibold text-slate-400 hover:text-slate-300 py-1 cursor-pointer bg-transparent border-none"
              >
                <span>Technical Metadata ({rawEntries.length} attributes)</span>
                <span className="font-mono text-slate-500">{rawExpanded ? "▲ Hide" : "▼ Show"}</span>
              </button>

              {rawExpanded && (
                <div className="mt-2.5 bg-slate-950 rounded-lg border border-slate-800/80 divide-y divide-slate-800/60 max-h-64 overflow-y-auto">
                  {rawEntries.map(([key, value]) => (
                    <div key={key} className="flex flex-col sm:flex-row sm:justify-between sm:gap-2 px-3 py-1.5 text-[11px]">
                      <span className="text-slate-400 font-mono shrink-0">{key}</span>
                      <span className="text-slate-300 sm:text-right font-mono break-all">
                        {typeof value === "object" ? JSON.stringify(value) : String(value ?? "—")}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
