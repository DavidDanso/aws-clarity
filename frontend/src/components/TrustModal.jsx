import { useEffect } from "react";

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
                Verifiable security architecture, tenant isolation, and data boundaries.
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

        <div className="p-5 space-y-5 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🔒</span>
                <span className="font-semibold text-slate-200">Strictly Read-Only</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Requests exclusively least-privilege <code className="text-teal-300">Describe*</code>, <code className="text-teal-300">List*</code>, and <code className="text-teal-300">Get*</code> IAM actions across the 10 supported services. Cannot create, modify, or delete resources.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🛡</span>
                <span className="font-semibold text-slate-200">Unique External ID & Tenant Isolation</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Generates a unique per-user <code className="text-teal-300">sts:ExternalId</code> to prevent confused-deputy attacks, and protects every scan result behind a 256-bit ephemeral <code className="text-teal-300">X-Scan-Token</code> (SHA-256 verified).
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">⏱</span>
                <span className="font-semibold text-slate-200">Temporary STS & Zero Key Storage</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Uses 1-hour <code className="text-teal-300">sts:AssumeRole</code> tokens held strictly in ephemeral Lambda memory. Your Role ARN and External ID are never stored in DynamoDB.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">💸</span>
                <span className="font-semibold text-slate-200">Zero Paid AWS APIs</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Makes zero Cost Explorer, GuardDuty, AWS Config, or Security Hub API calls. Unused and wasteful resources are identified purely from free configuration metadata.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Data Boundaries & Retention
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 leading-relaxed">
              <p>
                <strong className="text-slate-100">What is never accessed:</strong> S3 object contents, RDS/DynamoDB rows, Lambda source code, CloudWatch log events, AWS passwords, or billing invoices.
              </p>
              <p>
                <strong className="text-slate-100">Auto-expiring cache:</strong> Compressed, encrypted scan results expire automatically in DynamoDB after 1 hour via TTL and are inaccessible without the session&apos;s <code className="text-teal-300">X-Scan-Token</code>.
              </p>
              <p>
                <strong className="text-slate-100">Instant Revocation:</strong> Delete the IAM role or modify its trust policy in AWS IAM at any second to permanently cut off access.
              </p>
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">
            Verified against actual IAM policies and backend STS implementation
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
