import { useEffect, useState } from "react";
import { IAM_POLICY_JSON, PERMISSION_PREVIEW_GROUPS } from "../utils/constants";

export default function TrustModal({ isOpen, onClose, dataControls = null }) {
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

  const handleCopyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(IAM_POLICY_JSON);
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
      setTimeout(() => setDataNotice(""), 3000);
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
                Trust &amp; Privacy Centre
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Plain-language explanation of permissions, data flow, retention, and how to disconnect.
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
          {/* 1. What AWS Clarity Can Access */}
          <section className="space-y-2.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              1. What AWS Clarity Can Access
            </h4>
            <p className="text-slate-300">
              AWS Clarity connects using a read-only IAM role that <strong>you create</strong> in your own AWS account,
              protected by a unique <code className="text-teal-300">sts:ExternalId</code>. When you run a verification or scan,
              AWS Clarity requests temporary <strong>1-hour AWS STS credentials</strong>—it never asks for AWS access keys,
              secret keys, or root credentials, and it has <strong>zero permissions</strong> to create, modify, stop, or delete
              any AWS resource.
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
                  <p className="text-slate-400 text-[11px]">{grp.summary}</p>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowPolicyJson((prev) => !prev)}
                className="text-xs font-medium text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0"
              >
                {showPolicyJson ? "Hide exact 35-action IAM policy JSON ▲" : "Inspect exact 35-action IAM policy JSON ▼"}
              </button>
              <button
                type="button"
                onClick={handleCopyPolicy}
                className="text-xs font-medium text-slate-300 hover:text-white px-2.5 py-1 rounded border border-slate-700 bg-slate-800/60 cursor-pointer"
              >
                {copiedPolicy ? "Copied Policy JSON ✓" : "Copy Policy JSON"}
              </button>
            </div>

            {showPolicyJson && (
              <pre className="text-[10px] text-slate-300 p-3 overflow-x-auto max-h-52 font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800">
                {IAM_POLICY_JSON}
              </pre>
            )}
          </section>

          {/* 2. What AWS Clarity Collects (and Never Reads) */}
          <section className="space-y-2.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              2. What AWS Clarity Collects — and What It Never Reads
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <p className="font-semibold text-slate-200">Configuration Metadata Collected (10 Services)</p>
                <p className="text-slate-400 text-[11px]">
                  Resource identifiers, regions, states, tags, firewall ingress rules, VPC/NAT/IGW relationships, S3 public
                  access/encryption/versioning settings, IAM role/user policies &amp; MFA/key dates, Lambda runtime/modified dates,
                  RDS/DynamoDB/EBS configuration flags, CloudWatch alarm states/log retention, and CloudTrail status.
                </p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <p className="font-semibold text-emerald-300">Never Accessed or Read</p>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-400 text-[11px]">
                  <li>S3 object listings or contents (no <code className="text-slate-300">s3:ListBucket</code> or <code className="text-slate-300">s3:GetObject</code>)</li>
                  <li>RDS database rows or queries</li>
                  <li>DynamoDB table items or records</li>
                  <li>Lambda function source code</li>
                  <li>CloudWatch log events</li>
                  <li>Application secrets, IAM passwords, or secret keys</li>
                </ul>
              </div>
            </div>
          </section>

          {/* 3. Where Your Information Goes */}
          <section className="space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              3. Where Customer Information Goes
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 text-[11px]">
              <p className="text-slate-400">
                Hosted scans are <strong>not</strong> processed solely inside your browser. Resource metadata is processed
                through AWS Clarity&apos;s AWS Lambda backend as follows:
              </p>
              <ol className="list-decimal pl-4 space-y-1">
                <li>You enter your IAM Role ARN and stable External ID in the browser.</li>
                <li>AWS Clarity&apos;s Lambda backend calls <code className="text-teal-300">sts:AssumeRole</code> against your role.</li>
                <li>AWS STS issues temporary 1-hour read-only credentials held only in Lambda memory.</li>
                <li>Collectors read supported configuration metadata across your enabled AWS regions.</li>
                <li>The deterministic rule engine evaluates findings, evidence, and coverage status.</li>
                <li>The assessment is returned over HTTPS to your browser dashboard.</li>
              </ol>
            </div>
          </section>

          {/* 4. Data Retention & Logs */}
          <section className="space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              4. Data Retention &amp; Application Logs
            </h4>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-slate-300 text-[11px]">
              <p>
                <strong className="text-slate-100">Synchronous scans (default):</strong> Results are returned directly in the
                HTTPS response and are <strong>not</strong> written to DynamoDB. Only a short-lived rate-limit hash (SHA-256 of
                the Role ARN—never the raw ARN) and active-scan guard counter are touched to prevent abuse.
              </p>
              <p>
                <strong className="text-slate-100">Asynchronous scans (fallback for large accounts):</strong> Gzipped scan
                results are stored temporarily in DynamoDB behind a 256-bit <code className="text-teal-300">X-Scan-Token</code>{" "}
                (SHA-256 verified) with a <strong>1-hour TTL</strong>. Note: DynamoDB TTL deletion is asynchronous and AWS may
                remove expired items slightly after the exact 1-hour mark. Role ARNs and External IDs are never stored in DynamoDB.
              </p>
              <p>
                <strong className="text-slate-100">Your browser:</strong> Real scan results and previous scan diffs are kept in{" "}
                <code className="text-slate-200">sessionStorage</code> (cleared when the tab closes or when you click Clear below).
                Your stable External ID and last Role ARN (never credentials) are remembered in{" "}
                <code className="text-slate-200">localStorage</code> for convenience until you forget them.
              </p>
              <p>
                <strong className="text-slate-100">Backend logs:</strong> AWS Lambda writes standard execution metadata
                (request ID, duration, memory) to CloudWatch Logs with a <strong>14-day retention</strong>. Role ARNs, External IDs,
                STS credentials, and customer scan inventories are not logged.
              </p>
              <p>
                <strong className="text-slate-100">Public endpoint security model:</strong> AWS Clarity does not require user
                registration. On async scans, <code className="text-teal-300">X-Scan-Token</code> isolates scan result retrieval
                between users. Separately, because <code className="text-slate-200">POST /scan</code> is public, anyone who knows
                <strong> both</strong> your IAM Role ARN and your exact <code className="text-teal-300">sts:ExternalId</code>{" "}
                could trigger a read-only scan against that role. Always use the unique random External ID generated in Step 2
                (avoid predictable values such as <code className="text-slate-300">aws-clarity-scan</code>) and delete your role
                in AWS IAM whenever you are finished evaluating.
              </p>
            </div>
          </section>

          {/* 5. Data Controls & How to Disconnect */}
          <section className="space-y-3">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              5. Data Controls &amp; How to Disconnect
            </h4>

            {/* Unmistakable warning banner */}
            <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-500/35 text-amber-200 text-[11px] leading-relaxed">
              <strong>Important:</strong> Clearing data in this browser only removes information stored on your device. It does{" "}
              <strong>not</strong> revoke AWS Clarity&apos;s permission to assume your IAM role in AWS. To revoke AWS access,
              complete <strong>Action C</strong> in your AWS account below.
            </div>

            {dataNotice && (
              <div className="px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-[11px]">
                ✓ {dataNotice}
              </div>
            )}

            {/* Action A: Clear Local Scan Data */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5 text-[11px]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-semibold text-slate-100">A. Clear Local Scan Data (This Browser Only)</p>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                  Does NOT revoke AWS access
                </span>
              </div>
              <p className="text-slate-400">
                Deletes the current scan inventory, findings, and previous scan diff history stored in this browser tab&apos;s{" "}
                <code className="text-slate-300">sessionStorage</code>. Your saved Role ARN and External ID stay remembered, and
                your AWS IAM role is untouched.
              </p>
              {dataControls && (
                <div className="flex flex-wrap gap-2 pt-0.5">
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearCurrentResults,
                        "Cleared local scan results and comparison history from this browser tab. Your AWS IAM role was not changed."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 cursor-pointer"
                  >
                    Clear Local Scan Data
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearScanHistory,
                        "Cleared previous scan diff history from this browser tab."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 cursor-pointer"
                  >
                    Clear Diff History Only
                  </button>
                </div>
              )}
            </div>

            {/* Action B: Forget Saved Connection Details */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5 text-[11px]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-semibold text-slate-100">B. Forget Saved Connection Details (This Browser Only)</p>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                  Does NOT revoke AWS access
                </span>
              </div>
              <p className="text-slate-400">
                Removes your remembered IAM Role ARN and saved External ID from this browser&apos;s{" "}
                <code className="text-slate-300">localStorage</code>.{" "}
                <strong className="text-slate-200">Recovery note:</strong> if you keep your IAM role in AWS, AWS Clarity will
                prepare a new External ID after forgetting. To reconnect to an existing role without recreating it, copy its{" "}
                <code className="text-slate-300">sts:ExternalId</code> from{" "}
                <strong>AWS IAM → Roles → [Your Role] → Trust relationships</strong> and paste it into Step 2.
              </p>
              {dataControls && (
                <div className="flex flex-wrap gap-2 pt-0.5">
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onForgetConnectionDetails,
                        "Forgot saved Role ARN and External ID from this browser. Your AWS IAM role is still active until removed in AWS."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 cursor-pointer"
                  >
                    Forget Saved Connection Details
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      runDataAction(
                        dataControls.onClearAllLocalData,
                        "Cleared all local scan data and saved connection details from this browser. Your AWS IAM role was NOT modified."
                      )
                    }
                    className="px-3 py-1.5 text-[11px] font-medium rounded-lg border border-red-800/60 bg-red-950/30 hover:bg-red-950/50 text-red-300 cursor-pointer"
                  >
                    Clear All Local Browser Data (A + B)
                  </button>
                </div>
              )}
            </div>

            {/* Action C: Revoke AWS Clarity Access */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-teal-500/30 space-y-2 text-[11px] text-slate-300">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-semibold text-teal-300">C. Revoke AWS Clarity Access (Required in Your AWS Account)</p>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-950/60 border border-teal-500/30 text-teal-300">
                  Revokes AWS access immediately
                </span>
              </div>
              <p className="text-slate-400">
                This is the <strong>only</strong> action that stops AWS Clarity from assuming your IAM role:
              </p>
              <ol className="list-decimal pl-4 space-y-1 text-slate-300">
                <li>
                  <strong>If you used the CloudFormation template:</strong> Open{" "}
                  <strong>AWS CloudFormation → Stacks</strong>, select the{" "}
                  <code className="text-teal-300">aws-clarity-readonly-role</code> stack, and click <strong>Delete</strong>.
                </li>
                <li>
                  <strong>If you created the role manually:</strong> Open <strong>AWS IAM → Roles</strong>, select your role
                  (e.g., <code className="text-teal-300">AWSClarityReadOnly</code>), and either <strong>Delete</strong> the
                  role or remove AWS Clarity&apos;s Account ID from its <strong>Trust relationships</strong> tab.
                </li>
                <li>AWS immediately rejects all future <code className="text-slate-200">sts:AssumeRole</code> calls.</li>
              </ol>
            </div>
          </section>

          {/* 6. Security Contact */}
          <section className="space-y-1.5">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-teal-400">
              6. Security Contact
            </h4>
            <p className="text-[11px] text-slate-400">
              Found a security vulnerability or privacy concern? Please report it privately via{" "}
              <a
                href="https://github.com/DavidDanso/aws-clarity/security/advisories/new"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
              >
                GitHub Security Advisories
              </a>{" "}
              or open a public issue on the{" "}
              <a
                href="https://github.com/DavidDanso/aws-clarity/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
              >
                AWS Clarity GitHub repository
              </a>
              .
            </p>
          </section>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 shrink-0">
          <span className="text-[11px] text-slate-500">
            Strictly read-only · Temporary 1h STS sessions · No customer data contents read
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
