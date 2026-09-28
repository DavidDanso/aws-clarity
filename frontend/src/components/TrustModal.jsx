import React from "react";

/**
 * TrustModal.jsx
 *
 * Verifiable, factual disclosure of AWS Clarity's security posture and data handling.
 * Strict Rule: Contains ONLY claims that can be verified from the actual implementation.
 * Zero unverified marketing statements or exaggerated claims.
 */
export default function TrustModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
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
              <h3 className="text-base font-bold text-white">Trust & Security Architecture</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Verifiable security facts, authentication model, and data boundaries.
              </p>
            </div>
          </div>
          <button
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
                <span className="font-semibold text-slate-200">Read-Only Architecture</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                AWS Clarity requests exclusively <code className="text-teal-300">Describe*</code>, <code className="text-teal-300">List*</code>, and <code className="text-teal-300">Get*</code> API permissions. It possesses zero IAM capability to create, update, terminate, or modify customer cloud resources.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">⏱</span>
                <span className="font-semibold text-slate-200">Temporary STS Credentials</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Authentication relies on AWS Security Token Service (<code className="text-teal-300">sts:AssumeRole</code>) with a strictly enforced 1-hour session duration (<code className="text-teal-300">DurationSeconds=3600</code>). Credentials automatically expire.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🔑</span>
                <span className="font-semibold text-slate-200">Zero Credential Storage</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                We never request, accept, or store AWS root passwords, IAM user credentials, or permanent secret access keys. Temporary tokens exist in ephemeral memory during the scan only.
              </p>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-teal-400 font-bold">🛡</span>
                <span className="font-semibold text-slate-200">Confused Deputy Protection</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Role assumption enforces an External ID (<code className="text-teal-300">aws-clarity-scan</code>) in the STS assume call, preventing the cross-customer confused deputy vulnerability per AWS IAM specifications.
              </p>
            </div>
          </div>

          {/* What Clarity Collects vs Does Not Collect */}
          <div className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Data Boundaries
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/20 space-y-2">
                <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>✓</span> What Clarity Collects
                </span>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  <li>Resource metadata (IDs, ARNs, names, tags)</li>
                  <li>Security configurations (firewall rules, encryption flags)</li>
                  <li>Public accessibility flags (ACLs, policies, CIDRs)</li>
                  <li>Inventory timestamps and region associations</li>
                </ul>
              </div>

              <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/20 space-y-2">
                <span className="text-[11px] font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>✕</span> What Clarity Never Collects
                </span>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  <li>Object contents inside S3 buckets</li>
                  <li>Database records, tables, or customer data</li>
                  <li>Application source code or server memory</li>
                  <li>AWS billing data, Cost Explorer, or invoices</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Retention & Revocation */}
          <div className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Data Retention & Instant Access Revocation
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 leading-relaxed">
              <p>
                <strong className="text-slate-100">Scan Results Storage:</strong> Point-in-time scan outputs are retained in an encrypted DynamoDB table (<code className="text-teal-300">aws-clarity-scans</code>) solely to power the user session and comparative history.
              </p>
              <p>
                <strong className="text-slate-100">How to Revoke Access Immediately:</strong> Because access is mediated entirely through the IAM Role you created in your AWS Console, you can permanently revoke access at any second by simply deleting the role or removing the trust relationship policy. AWS immediately rejects all subsequent STS assume requests.
              </p>
            </div>
          </div>

          {/* Security Contact */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-slate-400">
            <div>
              <p className="font-semibold text-slate-200">Security & Privacy Questions</p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Maintained by David Danso (AWS Cloud Engineer). For vulnerability disclosures or questions:
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
            Verified against actual IAM policies and backend STS implementation
          </span>
          <button
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
