import { useEffect } from "react";

/**
 * TrustModal.jsx
 *
 * Verifiable, factual disclosure of AWS Clarity's security posture,
 * read-only guarantees, External ID protection, and data lifecycle.
 */
export default function TrustModal({ isOpen, onClose }) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="trust-modal-title"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h3 id="trust-modal-title" className="text-base font-bold text-white">
                Trust & Security Architecture
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Verifiable security facts, authentication model, and data boundaries.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
            aria-label="Close Trust Center"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-5 text-xs">
          {/* Core Architecture Principles */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🔒</span>
                <span className="font-semibold text-slate-200">Strictly Read-Only</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                AWS Clarity requests exactly 25 read-only <code className="text-teal-300">Describe*</code>, <code className="text-teal-300">List*</code>, and <code className="text-teal-300">Get*</code> IAM actions. It has zero ability to create, modify, stop, or delete your resources.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">⏱</span>
                <span className="font-semibold text-slate-200">Temporary STS Credentials</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Uses <code className="text-teal-300">sts:AssumeRole</code> with a 1-hour duration (<code className="text-teal-300">DurationSeconds=3600</code>). Temporary credentials exist only in ephemeral Lambda memory during the scan.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🛡</span>
                <span className="font-semibold text-slate-200">External ID Tenant Isolation</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Supports custom or auto-generated per-account <code className="text-teal-300">sts:ExternalId</code> values to protect against cross-account confused deputy attacks per AWS IAM best practices.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">💸</span>
                <span className="font-semibold text-slate-200">Zero Paid AWS APIs</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Makes zero Cost Explorer, GuardDuty, AWS Config, or Security Hub API calls. Unused and cost-risk resources are identified purely from free resource metadata.
              </p>
            </div>
          </div>

          {/* Data Boundaries */}
          <div className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Data Boundaries
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/20 space-y-2">
                <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>✓</span> What Clarity Inspects
                </span>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  <li>Resource metadata (IDs, ARNs, names, tags, regions)</li>
                  <li>Security settings (ingress rules, encryption, IMDSv2)</li>
                  <li>Public access posture (S3 policies/ACLs, RDS flags)</li>
                  <li>Idle/waste indicators (unattached EBS, idle EIPs, NATs)</li>
                </ul>
              </div>

              <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/20 space-y-2">
                <span className="text-[11px] font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>✕</span> What Clarity Never Accesses
                </span>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  <li>S3 object files or contents</li>
                  <li>RDS / DynamoDB rows or customer records</li>
                  <li>Lambda source code or EC2 memory/SSH</li>
                  <li>AWS passwords, permanent keys, or billing invoices</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Retention & Revocation */}
          <div className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Short-Lived Retention & Instant Revocation
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 leading-relaxed">
              <p>
                <strong className="text-slate-100">1-Hour Auto-Expiring Scan Cache:</strong> Scan outputs are stored encrypted and compressed in DynamoDB (<code className="text-teal-300">aws-clarity-scans</code>) keyed by a random 122-bit UUIDv4 <code className="text-teal-300">scan_id</code> and automatically deleted via DynamoDB TTL after 1 hour. Your Role ARN is never stored in DynamoDB.
              </p>
              <p>
                <strong className="text-slate-100">Instant Access Revocation:</strong> Delete the IAM role or edit its trust policy in your AWS Console at any moment—AWS immediately blocks all future <code className="text-teal-300">sts:AssumeRole</code> calls.
              </p>
            </div>
          </div>

          {/* Security Contact */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-slate-400">
            <div>
              <p className="font-semibold text-slate-200">Security & Privacy Questions</p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Maintained by David Danso (AWS Cloud Engineer).
              </p>
            </div>
            <a
              href="https://github.com/DavidDanso/aws-clarity/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="text-teal-400 hover:text-teal-300 font-medium whitespace-nowrap"
            >
              Open GitHub Issue →
            </a>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">
            Verified against actual IAM policies and backend STS code
          </span>
          <button
            type="button"
            onClick={onClose}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-1.5 rounded-lg transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
