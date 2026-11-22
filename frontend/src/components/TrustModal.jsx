import { useEffect, useState } from "react";
import {
  IAM_POLICY_DEFAULT_JSON,
  IAM_POLICY_JSON,
  PERMISSION_PREVIEW_GROUPS,
} from "../utils/constants";
import { downloadLocalFile } from "../utils/reportSanitizer";

export default function TrustModal({ isOpen, onClose, dataControls = null }) {
  const [policyVariant, setPolicyVariant] = useState("default");
  const [showPolicyJson, setShowPolicyJson] = useState(false);
  const [copiedPolicy, setCopiedPolicy] = useState(false);
  const [dataNotice, setDataNotice] = useState("");

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const activePolicyJson =
    policyVariant === "with-s3" ? IAM_POLICY_JSON : IAM_POLICY_DEFAULT_JSON;

  const handleCopyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(activePolicyJson);
      setCopiedPolicy(true);
      setTimeout(() => setCopiedPolicy(false), 1800);
    } catch {
      // Ignore clipboard failures
    }
  };

  const runDataAction = (fn, message) => {
    if (typeof fn === "function") {
      fn();
      setDataNotice(message);
      setTimeout(() => setDataNotice(""), 3500);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-2.5 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="trust-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl max-w-3xl w-full max-h-[92dvh] sm:max-h-[88dvh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-start sm:items-center justify-between gap-3 p-4 sm:p-5 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400 shrink-0">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div className="min-w-0">
              <h3 id="trust-modal-title" className="text-sm sm:text-base font-bold text-white">
                Trust &amp; Privacy Centre (Local-First Architecture)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Plain-language explanation of permissions, network behaviour, security boundaries, and local data controls.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-9 h-9 sm:w-8 sm:h-8 shrink-0 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
            aria-label="Close Trust and Privacy Centre"
          >
            ✕
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-4 sm:p-5 overflow-y-auto flex-1 space-y-6 text-xs leading-relaxed">
          {/* 1. Privacy-First Local Architecture */}
          <section className="space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              1. Privacy-First Local Architecture
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 text-[11px]">
              <p>
                AWS Clarity does <strong>not</strong> run a central scanning backend, does <strong>not</strong> assume
                cross-account roles into your AWS account, and does <strong>not</strong> store customer inventories in a
                central database.
              </p>
              <ol className="list-decimal pl-4 space-y-1 text-slate-400">
                <li>You run the open-source <code className="text-teal-300">aws-clarity</code> Python CLI locally using your existing AWS CLI / IAM Identity Center profile.</li>
                <li>The CLI communicates directly with official AWS service endpoints via <code className="text-slate-300">boto3</code> and writes <code className="text-teal-300">aws-clarity-report.json</code> locally (permissions <code className="text-slate-300">0600</code>).</li>
                <li>You import that JSON file into this static website, where the browser parses and renders it strictly in-memory.</li>
                <li>Production builds enforce Content-Security-Policy <code className="text-teal-300">connect-src &apos;none&apos;</code> so the dashboard cannot upload reports or contact external analytics/APIs.</li>
              </ol>
            </div>
          </section>

          {/* 2. Customer AWS Permissions & Cost Transparency */}
          <section className="space-y-2.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              2. Read-Only Permissions &amp; Customer-Side API Costs
            </h4>
            <p className="text-slate-300">
              Attach the read-only policy below to your own IAM Identity Center permission set or existing read-only IAM
              role. You never create a trust relationship to an AWS Clarity AWS account.
            </p>

            <div className="rounded-xl bg-slate-950 border border-slate-800 divide-y divide-slate-800/70">
              {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                <div key={grp.service} className="p-3 space-y-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-slate-200">{grp.service}</span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {grp.actions.length} read-only action{grp.actions.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  <p className="text-[10px] text-teal-300/90">{grp.costNote}</p>
                  <p className="text-slate-400 text-[11px]">{grp.summary}</p>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setPolicyVariant("default")}
                  className={`text-[11px] px-2.5 py-1 rounded border cursor-pointer ${
                    policyVariant === "default"
                      ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                      : "bg-slate-950 border-slate-800 text-slate-400"
                  }`}
                >
                  28 Actions (Default)
                </button>
                <button
                  type="button"
                  onClick={() => setPolicyVariant("with-s3")}
                  className={`text-[11px] px-2.5 py-1 rounded border cursor-pointer ${
                    policyVariant === "with-s3"
                      ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                      : "bg-slate-950 border-slate-800 text-slate-400"
                  }`}
                >
                  34 Actions (With Optional S3)
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowPolicyJson((prev) => !prev)}
                  className="text-xs font-medium text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0"
                >
                  {showPolicyJson ? "Hide Policy JSON ▲" : "Inspect Policy JSON ▼"}
                </button>
                <button
                  type="button"
                  onClick={handleCopyPolicy}
                  className="text-xs font-medium text-slate-300 hover:text-white px-2.5 py-1 rounded border border-slate-700 bg-slate-800/60 cursor-pointer"
                >
                  {copiedPolicy ? "Copied ✓" : "Copy"}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    downloadLocalFile(
                      policyVariant === "with-s3"
                        ? "aws-clarity-readonly-policy-with-s3.json"
                        : "aws-clarity-readonly-policy-default.json",
                      `${activePolicyJson}\n`,
                      "application/json;charset=utf-8;"
                    )
                  }
                  className="text-xs font-medium text-teal-300 hover:text-teal-200 px-2.5 py-1 rounded border border-teal-500/30 bg-teal-500/10 cursor-pointer"
                >
                  Download
                </button>
              </div>
            </div>

            {showPolicyJson && (
              <pre className="text-[10px] text-slate-300 p-3 overflow-x-auto max-h-52 font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800">
                {activePolicyJson}
              </pre>
            )}
          </section>

          {/* 3. What Never Gets Read or Sent */}
          <section className="space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              3. Network Behaviour &amp; Data Never Accessed
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <p className="font-semibold text-slate-200">Scanner Network Endpoints</p>
                <p className="text-slate-400">
                  The local Python CLI contacts <strong>only</strong> official AWS service endpoints for the enabled
                  regions you scan (`sts`, `ec2`, `iam`, `lambda`, `rds`, `dynamodb`, `monitoring`, `logs`, `cloudtrail`,
                  and `s3` only if opted in). Zero telemetry, zero crash-reporting servers, zero AWS Clarity API calls.
                </p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <p className="font-semibold text-emerald-300">Never Accessed or Logged</p>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                  <li>S3 object listings or contents (no <code className="text-slate-300">s3:ListBucket</code> / <code className="text-slate-300">s3:GetObject</code>)</li>
                  <li>RDS rows, DynamoDB items, Lambda source code, or CloudWatch log events</li>
                  <li>AWS access keys, secret keys, session tokens, or IAM passwords</li>
                </ul>
              </div>
            </div>
          </section>

          {/* 4. Honest Security Boundaries */}
          <section className="space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              4. Honest Security Boundaries &amp; Verification
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-amber-500/30 space-y-2 text-[11px] text-slate-300">
              <p>
                No software can promise zero breach risk. Local-first substantially reduces blast radius by removing
                central credential access and central customer databases, <strong>however</strong>:
              </p>
              <ul className="list-disc pl-4 space-y-1 text-slate-400">
                <li>Read-only access prevents resource modification, but does not prevent metadata disclosure if your workstation or local report file is compromised.</li>
                <li>Software supply-chain attacks or malicious updates remain possible—always inspect releases and verify SHA-256 checksums in <code className="text-slate-300">SHA256SUMS.txt</code> against public source code.</li>
                <li>AWS Clarity is an independent open-source project and has not undergone third-party SOC 2 / penetration-test certification.</li>
              </ul>
            </div>
          </section>

          {/* 5. Local Data Controls */}
          <section className="space-y-2.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              5. Local Data Controls
            </h4>

            {dataNotice && (
              <div className="px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-[11px]">
                ✓ {dataNotice}
              </div>
            )}

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5 text-[11px]">
              <p className="text-slate-400">
                Imported reports stay strictly in browser memory and disappear automatically when you close this tab. You
                can also clear active in-memory reports or any residual browser storage below:
              </p>
              {dataControls && (
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearCurrentReport,
                        "Cleared the active in-memory assessment report."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 cursor-pointer"
                  >
                    Clear Current Assessment
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearDiffHistory,
                        "Cleared in-memory scan comparison history."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 cursor-pointer"
                  >
                    Clear Diff History
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearAllLocalData,
                        "Cleared all in-memory report data and any residual browser storage."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-red-800/60 bg-red-950/30 hover:bg-red-950/50 text-red-300 cursor-pointer"
                  >
                    Clear All Local Browser Data
                  </button>
                </div>
              )}
              <p className="text-[11px] text-slate-500">
                To remove report files from disk, delete your local <code className="text-slate-400">aws-clarity-report.json</code>{" "}
                file. To remove IAM permissions in AWS, detach the read-only policy from your IAM role or permission set.
              </p>
            </div>
          </section>

          {/* 6. Security Contact */}
          <section className="space-y-1.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              6. Security Vulnerability Reporting
            </h4>
            <p className="text-[11px] text-slate-400">
              Report security vulnerabilities privately via{" "}
              <a
                href="https://github.com/DavidDanso/aws-clarity/security/advisories/new"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
              >
                GitHub Security Advisories
              </a>{" "}
              (see <code className="text-slate-300">SECURITY.md</code> in the repository).
            </p>
          </section>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 shrink-0">
          <span className="text-[11px] text-slate-500">
            Local-only execution · Zero report uploads · Strictly read-only
          </span>
          <button
            type="button"
            onClick={onClose}
            className="w-full sm:w-auto bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-2 sm:py-1.5 rounded-lg transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
