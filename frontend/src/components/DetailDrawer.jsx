import { useState, useEffect, useRef } from "react";
import {
  CATEGORY_BADGE,
  RESOURCE_SERVICE_MAP,
  RESOURCE_TYPE_LABELS,
  STATUS_COLOR,
} from "../utils/constants";
import { useDialogFocus } from "../utils/useDialogFocus";

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
  UNUSED: {
    badge:  "text-sky-300 bg-sky-500/10 border border-sky-500/20",
    border: "border-sky-500/30",
    left:   "border-l-sky-500",
  },
  INFO: {
    badge:  "text-slate-300 bg-slate-500/15 border border-slate-600/40",
    border: "border-slate-700/70",
    left:   "border-l-slate-400",
  },
};

const RAW_SKIP_KEYS = [
  "tags", "security_groups", "attachments", "inline_policies", "attached_managed_policies",
  "trust_policy", "ebs_volumes", "iam_instance_profile", "role", "elastic_ip", "elastic_ips",
  "db_subnet_group_name", "public_ip", "private_ip", "subnet_ids", "ip_permissions",
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
      timeZoneName: "short",
    });
  } catch {
    return String(ts);
  }
}

function getDisplayedStatus(resource) {
  if (resource?.status === "HEALTHY" && resource?.assessment?.status !== "COMPLETE") {
    return "INCOMPLETE";
  }
  return resource?.status || "INCOMPLETE";
}

export default function DetailDrawer({ resource, onClose, scannedAt, history, previousScannedAt }) {
  const drawerRef = useRef(null);
  const [rawExpanded, setRawExpanded] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);

  const handleCopy = async (key, text) => {
    try {
      await navigator.clipboard.writeText(String(text));
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Ignore clipboard failures
    }
  };

  useDialogFocus(Boolean(resource), onClose, drawerRef);

  useEffect(() => {
    const handleClick = (e) => {
      if (drawerRef.current && !drawerRef.current.contains(e.target)) onClose();
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [onClose]);

  if (!resource || typeof resource !== "object") return null;

  const raw = resource.raw || {};
  const rawEntries = Object.entries(raw).filter(([key]) => !RAW_SKIP_KEYS.includes(key));
  const serviceName = resource.service || RESOURCE_SERVICE_MAP[resource.type] || "";

  const relatedItems = [];
  if (raw.vpc_id) relatedItems.push({ label: "VPC", value: raw.vpc_id });
  if (raw.subnet_id) relatedItems.push({ label: "Subnet(s)", value: raw.subnet_id });
  if (Array.isArray(raw.security_groups) && raw.security_groups.length > 0) {
    relatedItems.push({ label: "Security Groups", value: raw.security_groups.join(", ") });
  }
  if (Array.isArray(raw.ebs_volumes) && raw.ebs_volumes.length > 0) {
    relatedItems.push({ label: "Attached EBS Volumes", value: raw.ebs_volumes.join(", ") });
  }
  if (Array.isArray(raw.attachments) && raw.attachments.length > 0) {
    const attached = raw.attachments
      .map((a) => a.InstanceId || a.VpcId || a.instance_id || JSON.stringify(a))
      .join(", ");
    relatedItems.push({ label: "Attachments", value: attached });
  }
  if (raw.iam_instance_profile) relatedItems.push({ label: "IAM Instance Profile", value: raw.iam_instance_profile });
  if (raw.role) relatedItems.push({ label: "Execution IAM Role", value: raw.role });
  if (raw.elastic_ip) relatedItems.push({ label: "Elastic IP", value: raw.elastic_ip });
  if (raw.db_subnet_group_name) relatedItems.push({ label: "DB Subnet Group", value: raw.db_subnet_group_name });
  if (raw.s3_bucket_name) relatedItems.push({ label: "Target S3 Bucket", value: raw.s3_bucket_name });
  if (raw.public_ip) relatedItems.push({ label: "Public IP", value: raw.public_ip });
  if (raw.private_ip) relatedItems.push({ label: "Private IP", value: raw.private_ip });

  const resolvedScannedAt = resource.scanned_at || scannedAt;
  const displayedStatus = getDisplayedStatus(resource);
  const checks = Array.isArray(resource.assessment?.checks) ? resource.assessment.checks : [];
  const passedChecks = checks.filter((c) => c?.status === "PASSED");
  const failedChecks = checks.filter((c) => c?.status === "CHECK_FAILED");

  return (
    <div
      className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`Details for ${resource.name}`}
    >
      <div
        ref={drawerRef}
        tabIndex={-1}
        className="absolute right-0 top-0 h-[100dvh] w-full sm:w-[500px] md:w-[580px] max-w-full bg-slate-900 border-l border-slate-700/50 shadow-2xl overflow-y-auto animate-slide-in flex flex-col focus:outline-none"
      >
        {/* Sticky Header so Close button stays reachable on mobile */}
        <div className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur-md flex items-start justify-between p-4 sm:p-6 border-b border-slate-700/50 shrink-0">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-[11px] font-semibold text-teal-400 uppercase tracking-wider">
                {serviceName}
              </span>
              <span className="text-slate-400" aria-hidden="true">·</span>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                {RESOURCE_TYPE_LABELS[resource.type] || resource.type}
              </span>
              <span className={`text-[11px] font-bold px-2 py-0.5 rounded bg-slate-800/80 ${
                STATUS_COLOR[displayedStatus] || "text-slate-300"
              }`}>
                {displayedStatus}
              </span>
            </div>
            <h2 className="text-base sm:text-lg font-bold text-white truncate">{resource.name}</h2>
            <div className="flex items-center gap-2 mt-0.5 min-w-0">
              <p className="text-xs text-slate-400 font-mono truncate">{resource.id}</p>
              <button
                type="button"
                onClick={() => handleCopy("id", resource.id)}
                className="text-[11px] text-slate-400 hover:text-teal-300 shrink-0 cursor-pointer bg-transparent border-none p-0"
              >
                {copiedKey === "id" ? "Copied ✓" : "Copy ID"}
              </button>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="ml-3 w-9 h-9 shrink-0 flex items-center justify-center rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            aria-label="Close inspection drawer"
          >
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 sm:p-6 pb-8 space-y-6 flex-1">
          {/* Context Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 text-xs text-slate-400 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">AWS Region</span>
              <span className="font-mono text-slate-200">{resource.region || "global"}</span>
            </div>
            <div className="sm:text-right">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">Last Inspected</span>
              <span className="font-mono text-slate-200">{formatLastChecked(resolvedScannedAt)}</span>
            </div>
          </div>

          {/* Comparative Scan History */}
          {history && history.hasHistory && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                Verification Since Previous Scan
              </h3>
              <div className="bg-slate-950/60 rounded-xl border border-slate-800/80 p-3.5 space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3 pb-3 border-b border-slate-800/60">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold mb-1">Current</span>
                    <span className={`font-bold px-2 py-0.5 rounded text-[11px] bg-slate-800/80 ${STATUS_COLOR[displayedStatus] || "text-slate-300"}`}>
                      {displayedStatus}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold mb-1">Previous</span>
                    {history.previousStatus ? (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`font-bold px-2 py-0.5 rounded text-[11px] bg-slate-800/80 ${STATUS_COLOR[history.previousStatus] || "text-slate-300"}`}>
                          {history.previousStatus}
                        </span>
                        {previousScannedAt && (
                          <span className="text-slate-400 text-[10px] font-mono">
                            {formatLastChecked(previousScannedAt)}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-cyan-400 font-medium text-[11px] bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                        Newly Discovered
                      </span>
                    )}
                  </div>
                </div>

                {history.resolvedIssues?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider block">
                      Verified Resolved ({history.resolvedIssues.length})
                    </span>
                    {history.resolvedIssues.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-emerald-950/30 text-emerald-300">
                        <span className="font-bold shrink-0">✓</span>
                        {item.ruleId && <span className="text-[10px] font-mono shrink-0">{item.ruleId}</span>}
                        <span className="truncate">{item.title}</span>
                      </div>
                    ))}
                  </div>
                )}

                {history.unverifiedIssues?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-orange-400 tracking-wider block">
                      Unverified — Incomplete Scan ({history.unverifiedIssues.length})
                    </span>
                    {history.unverifiedIssues.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-orange-950/30 text-orange-200">
                        <span className="font-bold shrink-0">?</span>
                        {item.ruleId && <span className="text-[10px] font-mono shrink-0">{item.ruleId}</span>}
                        <span className="truncate">{item.title}</span>
                      </div>
                    ))}
                  </div>
                )}

                {history.newIssues?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-cyan-400 tracking-wider block">
                      Newly Detected ({history.newIssues.length})
                    </span>
                    {history.newIssues.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2 py-1 px-2 rounded bg-cyan-950/30 text-cyan-300">
                        <span className="font-bold shrink-0">⚡</span>
                        {item.ruleId && <span className="text-[10px] font-mono shrink-0">{item.ruleId}</span>}
                        <span className="truncate">{item.title}</span>
                      </div>
                    ))}
                  </div>
                )}

                {!history.isNew && !history.resolvedIssues?.length && !history.newIssues?.length && (
                  <p className="text-slate-400 italic">No finding changes since the previous scan.</p>
                )}
              </div>
            </div>
          )}

          {/* Findings Section */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200">
                Findings ({resource.issues?.length || 0})
              </h3>
              <span className="text-[11px] text-slate-400">Deterministic rule evaluation</span>
            </div>

            {failedChecks.length > 0 && (
              <div className="mb-3 rounded-lg border border-orange-500/30 bg-orange-950/20 px-3 py-2.5 text-xs text-orange-200">
                <p className="font-semibold text-orange-300">
                  Incomplete Assessment ({failedChecks.length} check{failedChecks.length === 1 ? "" : "s"} blocked)
                </p>
                <p className="text-[11px] text-orange-200/80 mt-0.5">
                  This resource cannot be marked Healthy until all applicable checks run cleanly:
                </p>
                <ul className="mt-1.5 list-disc pl-4 space-y-0.5 text-[11px]">
                  {failedChecks.map((chk, idx) => (
                    <li key={`${chk.rule_id}-${idx}`}>
                      <span className="font-mono font-semibold">{chk.rule_id}:</span> {chk.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {!resource.issues || resource.issues.length === 0 ? (
              displayedStatus === "HEALTHY" ? (
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-4 flex items-center gap-3 text-sm text-emerald-400">
                  <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                  <div>
                    <p className="font-medium text-emerald-300">Verified Healthy</p>
                    <p className="text-xs text-emerald-500 mt-0.5">
                      All {passedChecks.length} applicable check{passedChecks.length === 1 ? "" : "s"} executed and passed.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-orange-500/25 bg-orange-950/10 p-4 text-xs text-orange-200">
                  No findings were triggered by the checks that ran, but one or more checks failed due to missing permissions or API errors (listed above).
                </div>
              )
            ) : (
              <div className="space-y-4">
                {resource.issues.map((issue, idx) => {
                  const style = SEVERITY_STYLE[issue.severity] || SEVERITY_STYLE.WARNING;
                  const evidenceEntries = issue.evidence ? Object.entries(issue.evidence) : [];
                  const copyId = `fix-${idx}`;

                  return (
                    <div
                      key={`${issue.rule_id || idx}-${idx}`}
                      className={`rounded-xl border ${style.border} border-l-4 ${style.left} bg-slate-900/90 overflow-hidden shadow-sm`}
                    >
                      <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800/60 flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2 flex-wrap">
                          {issue.rule_id && (
                            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded shrink-0 ${style.badge}`}>
                              {issue.rule_id}
                            </span>
                          )}
                          <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                            CATEGORY_BADGE[issue.category] || "bg-slate-800 text-slate-400 border-slate-700"
                          }`}>
                            {issue.category}
                          </span>
                          <span className={`text-[11px] font-bold uppercase tracking-wider ${style.badge.split(" ")[0]}`}>
                            {issue.severity === "INFO" ? "INFO · Review Note" : issue.severity}
                          </span>
                        </div>
                        {issue.severity === "INFO" && (
                          <span className="text-[10px] text-slate-400">
                            0 score impact · often legitimate
                          </span>
                        )}
                      </div>

                      <div className="p-4 space-y-3 text-xs">
                        {/* Actual Problem */}
                        <h4 className="text-sm font-semibold text-slate-100 leading-snug">{issue.title}</h4>

                        {/* Affected Resource */}
                        <div className="text-[11px] font-mono text-slate-400 bg-slate-950/50 px-2.5 py-1.5 rounded border border-slate-800/60 break-all">
                          Affected: <span className="text-slate-200">{resource.name}</span> ({resource.id} · {resource.region || "global"})
                        </div>

                        {issue.what_found && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              Problem Details
                            </span>
                            <p className="text-slate-200 leading-relaxed bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/70 break-words">
                              {issue.what_found}
                            </p>
                          </div>
                        )}

                        {issue.why && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              Why It Matters
                            </span>
                            <p className="text-slate-300 leading-relaxed break-words">{issue.why}</p>
                          </div>
                        )}

                        {evidenceEntries.length > 0 && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                              Supporting AWS Evidence
                            </span>
                            <div className="rounded-lg bg-slate-950 border border-slate-800/80 divide-y divide-slate-800/60 overflow-hidden font-mono text-[11px]">
                              {evidenceEntries.map(([k, v]) => (
                                <div key={k} className="flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-0.5 sm:gap-3 px-3 py-1.5">
                                  <span className="text-slate-400 shrink-0">{k}:</span>
                                  <span className="text-slate-100 sm:text-right break-all">
                                    {typeof v === "object" ? JSON.stringify(v) : String(v)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {issue.impact && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 block mb-1">
                              Before You Change (Impact &amp; Dependencies)
                            </span>
                            <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 text-amber-200/90 leading-relaxed text-[11px] break-words">
                              {issue.impact}
                            </div>
                          </div>
                        )}

                        {issue.fix && (
                          <div className="pt-1">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                              <span className="text-[10px] font-bold uppercase tracking-wider text-teal-400">
                                How to Resolve (Manual in AWS)
                              </span>
                              <button
                                type="button"
                                onClick={() => handleCopy(copyId, issue.fix)}
                                className="text-[10px] text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0"
                              >
                                {copiedKey === copyId ? "Copied ✓" : "Copy steps"}
                              </button>
                            </div>
                            <div className="p-3 rounded-lg bg-teal-950/20 border border-teal-500/20 text-teal-200 leading-relaxed text-[12px] break-words">
                              {issue.fix}
                            </div>
                          </div>
                        )}

                        {issue.verify && (
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 block mb-1">
                              How to Verify the Fix
                            </span>
                            <div className="p-2.5 rounded-lg bg-emerald-950/15 border border-emerald-500/20 text-emerald-200/90 leading-relaxed text-[11px] break-words">
                              {issue.verify}
                            </div>
                          </div>
                        )}

                        <p className="text-[10px] text-slate-400">Checked: {issue.what_checked}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {passedChecks.length > 0 && (
              <div className="mt-4 pt-3 border-t border-slate-800/60">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Verified Passing Checks ({passedChecks.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {passedChecks.map((c) => (
                    <span
                      key={c.rule_id}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/30 border border-emerald-500/20 text-emerald-400"
                    >
                      ✓ {c.rule_id}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Related Infrastructure */}
          {relatedItems.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Related Infrastructure
              </h3>
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

          {/* Raw Technical Metadata */}
          {rawEntries.length > 0 && (
            <div className="border-t border-slate-800/80 pt-4">
              <button
                type="button"
                onClick={() => setRawExpanded((prev) => !prev)}
                className="flex items-center justify-between w-full text-left text-xs font-semibold text-slate-400 hover:text-slate-300 py-1 cursor-pointer bg-transparent border-none"
              >
                <span>Raw AWS Configuration Attributes ({rawEntries.length})</span>
                <span className="font-mono text-slate-400">{rawExpanded ? "▲ Hide" : "▼ Show"}</span>
              </button>

              {rawExpanded && (
                <div
                  tabIndex={0}
                  role="region"
                  aria-label="Raw AWS configuration attributes"
                  className="mt-2.5 bg-slate-950 rounded-lg border border-slate-800/80 divide-y divide-slate-800/60 max-h-64 overflow-y-auto"
                >
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
