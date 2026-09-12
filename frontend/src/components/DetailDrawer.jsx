import { useEffect, useRef } from "react";

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

// Keys to skip in the raw metadata section (shown via structured UI instead)
const RAW_SKIP_KEYS = [
  "tags", "security_groups", "attachments", "inline_policies", "attached_managed_policies",
  "trust_policy", "ebs_volumes", "iam_instance_profile", "role", "elastic_ip", "elastic_ips",
  "db_subnet_group_name", "public_ip", "private_ip", "subnet_ids"
];

export default function DetailDrawer({ resource, onClose }) {
  const drawerRef = useRef(null);

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

  return (
    <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm">
      <div
        ref={drawerRef}
        className="absolute right-0 top-0 h-full w-full sm:w-[440px] md:w-[500px] bg-slate-900 border-l border-slate-700/50 shadow-2xl overflow-y-auto animate-slide-in"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 sm:p-6 border-b border-slate-700/50">
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-bold text-white truncate">{resource.name}</h2>
            <p className="text-xs text-slate-500 mt-1 font-mono truncate">{resource.id}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-4 w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 sm:p-6 space-y-6">

          {/* Type & Status */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-xs text-slate-500 uppercase tracking-wider">Type</span>
              <p className="text-sm text-slate-200 mt-1">{resource.type}</p>
            </div>
            <div>
              <span className="text-xs text-slate-500 uppercase tracking-wider">Status</span>
              <p className={`text-sm font-semibold mt-1 ${STATUS_COLOR[resource.status] || "text-slate-200"}`}>
                {resource.status}
              </p>
            </div>
            {resource.region && (
              <div>
                <span className="text-xs text-slate-500 uppercase tracking-wider">Region</span>
                <p className="text-sm text-slate-200 mt-1">{resource.region}</p>
              </div>
            )}
          </div>

          {/* ── Issues — structured evidence-based findings ────────────────── */}
          <div>
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Findings ({resource.issues.length})
            </h3>

            {resource.issues.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-emerald-400">
                <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                No issues detected.
              </div>
            ) : (
              <div className="space-y-4">
                {resource.issues.map((issue, idx) => {
                  const style = SEVERITY_STYLE[issue.severity] || SEVERITY_STYLE.WARNING;
                  const evidenceEntries = issue.evidence
                    ? Object.entries(issue.evidence)
                    : [];

                  return (
                    <div
                      key={idx}
                      className={`rounded-lg border ${style.border} border-l-4 ${style.left} overflow-hidden`}
                    >
                      {/* Finding header */}
                      <div className="px-4 pt-3 pb-2 flex items-start gap-2 justify-between">
                        <div className="flex flex-col gap-1 min-w-0">
                          {/* Rule ID + Severity */}
                          <div className="flex items-center gap-2 flex-wrap">
                            {issue.rule_id && (
                              <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0 ${style.badge}`}>
                                {issue.rule_id}
                              </span>
                            )}
                            <span className={`text-[10px] font-semibold uppercase tracking-wider shrink-0 ${style.badge.split(" ")[0]}`}>
                              {issue.severity}
                            </span>
                          </div>
                          {/* Plain-English title */}
                          <p className="text-sm font-semibold text-slate-100 leading-snug">
                            {issue.title || issue.message}
                          </p>
                        </div>
                      </div>

                      {/* Why it matters */}
                      {issue.why && (
                        <div className="px-4 pb-2">
                          <p className="text-[12px] text-slate-400 leading-relaxed">{issue.why}</p>
                        </div>
                      )}

                      {/* Evidence block */}
                      {evidenceEntries.length > 0 && (
                        <div className="mx-4 mb-3 rounded-md bg-slate-800/80 border border-slate-700/40 divide-y divide-slate-700/30">
                          <p className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Evidence</p>
                          {evidenceEntries.map(([k, v]) => (
                            <div key={k} className="flex justify-between gap-3 px-3 py-1.5 text-[12px]">
                              <span className="text-slate-400 shrink-0">{k}</span>
                              <span className="text-slate-100 font-mono text-right break-all">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Fix */}
                      {issue.fix && (
                        <div className="px-4 pb-3">
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">How to fix</p>
                          <p className="text-[12px] text-slate-300 leading-relaxed">{issue.fix}</p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* ── Related Resources ────────────────────────────────────────────── */}
          {relatedItems.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Related Resources</h3>
              <div className="bg-slate-800/60 rounded-lg border border-slate-700/50 divide-y divide-slate-700/30">
                {relatedItems.map(({ label, value }) => (
                  <div key={label} className="flex flex-col sm:flex-row sm:justify-between sm:gap-2 px-4 py-2.5 text-sm">
                    <span className="text-slate-400 shrink-0">{label}</span>
                    <span className="text-slate-200 sm:text-right font-mono text-sm break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Raw Metadata ─────────────────────────────────────────────────── */}
          {rawEntries.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Metadata</h3>
              <div className="bg-slate-800/80 rounded-lg border border-slate-700/50 divide-y divide-slate-700/30">
                {rawEntries.map(([key, value]) => (
                  <div key={key} className="flex flex-col sm:flex-row sm:justify-between sm:gap-2 px-4 py-2.5 text-sm">
                    <span className="text-slate-400 shrink-0">{key}</span>
                    <span className="text-slate-200 sm:text-right font-mono text-sm break-all">
                      {String(value ?? "—")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
