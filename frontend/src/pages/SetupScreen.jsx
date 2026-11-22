import { useState } from "react";
import {
  generateExternalId,
  maskAccountId,
  validateExternalId,
  validateRoleArn,
} from "../utils/formatters";
import {
  IAM_POLICY_JSON,
  SERVICE_COVERAGE_MATRIX,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import { checkPermissions } from "../services/api";
import TrustModal from "../components/TrustModal";

const FAQ_ITEMS = [
  {
    question: "Is AWS Clarity safe to connect to a real AWS account?",
    answer:
      "Yes. AWS Clarity assumes a strictly read-only IAM role via temporary 1-hour AWS STS credentials and enforces your unique External ID. It has zero permissions to create, modify, stop, or delete any resources.",
  },
  {
    question: "Does AWS Clarity scan all of my AWS regions?",
    answer:
      "Yes. On every scan, AWS Clarity queries ec2:DescribeRegions to discover every enabled AWS region in your account, scans regional services across all of them with full pagination, and collects global services (S3, IAM) once with zero duplicates.",
  },
  {
    question: "Will scanning my account create AWS charges?",
    answer:
      "AWS Clarity deliberately avoids paid AWS APIs (zero Cost Explorer, AWS Config, GuardDuty, or Security Hub calls). Resource discovery uses free Describe/List/Get control-plane APIs, plus 1 lightweight S3 ListObjectsV2 call per bucket.",
  },
  {
    question: "What happens if my role is missing a permission or a region fails?",
    answer:
      "AWS Clarity never hides errors or marks incomplete scans as successful. The scan is explicitly marked INCOMPLETE, and Scan Coverage lists the exact affected service, region, reason, and missing IAM permission.",
  },
  {
    question: "How do I revoke access?",
    answer:
      "Delete the IAM role or edit its trust policy in AWS IAM at any time. AWS immediately blocks all future sts:AssumeRole requests.",
  },
];

export default function SetupScreen({
  onScanStart,
  onResumeSession = null,
  resumableAccountId = "",
  initialRoleArn = "",
  initialExternalId = "",
  scanError,
  setScanError,
}) {
  const [roleArn, setRoleArn] = useState(initialRoleArn);
  const [externalId, setExternalId] = useState(initialExternalId || generateExternalId());
  const [localError, setLocalError] = useState("");
  const [copiedKey, setCopiedKey] = useState(null);
  const [openFaq, setOpenFaq] = useState(null);
  const [showMatrix, setShowMatrix] = useState(false);
  const [showRoleGuide, setShowRoleGuide] = useState(true);

  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyData, setVerifyData] = useState(null);
  const [verifyError, setVerifyError] = useState(null);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  const effectiveExternalId = externalId.trim();

  const handleCopy = async (key, text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Ignore clipboard failures
    }
  };

  const validateInputs = () => {
    if (!roleArn.trim()) {
      setLocalError("IAM Role ARN is required.");
      return false;
    }
    if (!validateRoleArn(roleArn.trim())) {
      setLocalError("Invalid Role ARN format. Expected: arn:aws:iam::123456789012:role/RoleName");
      return false;
    }
    if (!effectiveExternalId || !validateExternalId(effectiveExternalId)) {
      setLocalError("External ID must be 2–128 characters using letters, numbers, or +=,.@:/_-");
      return false;
    }
    return true;
  };

  const handleVerify = async () => {
    setLocalError("");
    setScanError("");
    setVerifyError(null);
    if (!validateInputs()) return;

    setIsVerifying(true);
    try {
      const resp = await checkPermissions(roleArn.trim(), effectiveExternalId);
      setVerifyData(resp);
    } catch (err) {
      setVerifyData(null);
      setVerifyError(err.message || "Failed to verify account connection.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setLocalError("");
    setScanError("");
    if (!validateInputs()) return;
    onScanStart(roleArn.trim(), effectiveExternalId);
  };

  const activeError = localError || scanError;
  const appAccountId = import.meta.env.VITE_APP_ACCOUNT_ID || "Set VITE_APP_ACCOUNT_ID";

  return (
    <div className="min-h-[100dvh] bg-slate-950 flex flex-col items-center justify-start px-3.5 sm:px-6 lg:px-8 py-6 sm:py-10 lg:py-12 pb-20 sm:pb-16 text-slate-100">
      <div className="w-full max-w-2xl lg:max-w-3xl flex flex-col space-y-6 sm:space-y-7">
        {/* Top Brand & Hero */}
        <header className="flex flex-col items-center text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-[11px] sm:text-xs font-medium max-w-full">
            <svg className="shrink-0" xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span className="truncate">AWS Clarity · Strictly Read-Only Account Visibility</span>
          </div>
          <h1 className="text-xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight max-w-2xl leading-tight">
            See Every Resource, Security Risk &amp; Cost Leak in Your AWS Account
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl leading-relaxed">
            Connect with a read-only IAM Role ARN and your unique External ID. AWS Clarity scans all enabled regions across 10 core AWS services—giving you complete inventory, evidence-backed findings, and step-by-step remediation without navigating dozens of AWS Console pages.
          </p>
        </header>

        {/* Resume Current Tab Scan (optional convenience without bypassing landing screen) */}
        {onResumeSession && (
          <div className="rounded-xl border border-teal-500/30 bg-teal-950/20 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs">
            <span className="text-teal-200">
              You have an active scan session in this browser tab for{" "}
              <span className="font-mono font-semibold">Account {maskAccountId(resumableAccountId)}</span>.
            </span>
            <button
              type="button"
              onClick={onResumeSession}
              className="text-xs font-semibold text-teal-300 hover:text-teal-200 underline underline-offset-2 cursor-pointer bg-transparent border-none p-0 self-start sm:self-auto"
            >
              Return to Dashboard →
            </button>
          </div>
        )}

        {/* 10 Supported AWS Services + Explicit Coverage Matrix */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 sm:p-5 space-y-3.5">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                10 Supported AWS Services (v1 Fixed Scope)
              </p>
              <p className="text-[11px] text-slate-500 mt-0.5">
                All enabled regions discovered automatically · Full API pagination · Global services deduplicated
              </p>
            </div>
            <button
              type="button"
              onClick={() => setShowMatrix((prev) => !prev)}
              className="text-xs font-medium text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0"
            >
              {showMatrix ? "Hide coverage matrix ▲" : "View resource coverage matrix ▼"}
            </button>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {SUPPORTED_SERVICES.map((svc) => (
              <span
                key={svc}
                className="text-xs font-medium px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-200"
              >
                {svc}
              </span>
            ))}
          </div>

          {showMatrix && (
            <div className="pt-2 space-y-2 text-[11px]">
              <div className="rounded-lg border border-slate-800 bg-slate-950 divide-y divide-slate-800/70 overflow-hidden">
                {SERVICE_COVERAGE_MATRIX.map((row) => (
                  <div key={row.service} className="p-2.5 grid grid-cols-1 sm:grid-cols-12 gap-1.5 sm:gap-3">
                    <div className="sm:col-span-3">
                      <span className="font-semibold text-teal-300">{row.service}</span>
                      <span className="block text-[10px] text-slate-500">{row.scope}</span>
                    </div>
                    <div className="sm:col-span-4 text-slate-300">
                      {row.resources.join(", ")}
                    </div>
                    <div className="sm:col-span-5 text-slate-400 leading-relaxed">
                      {row.checks}
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-500">
                Out of scope in v1: Cost Explorer APIs (paid), GuardDuty/Config/Security Hub (paid), other AWS services, and customer data contents.
              </p>
            </div>
          )}
        </section>

        {/* Connect Account Form */}
        <form onSubmit={handleSubmit} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-white">Connect Your AWS Account</h2>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-xs text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
            >
              Security &amp; Trust Details →
            </button>
          </div>

          {/* External ID (Unique per user/session) */}
          <div className="space-y-1.5">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-2">
              <label htmlFor="external-id-input" className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                1. Your Unique External ID
              </label>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <button
                  type="button"
                  onClick={() => handleCopy("extid", effectiveExternalId)}
                  className="text-[11px] text-slate-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none py-0.5 px-0"
                >
                  {copiedKey === "extid" ? "Copied ✓" : "Copy"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setExternalId("aws-clarity-scan");
                    setVerifyData(null);
                  }}
                  className="text-[11px] text-slate-400 hover:text-slate-200 font-medium cursor-pointer bg-transparent border-none py-0.5 px-0"
                >
                  Use default
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setExternalId(generateExternalId());
                    setVerifyData(null);
                  }}
                  className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none py-0.5 px-0"
                >
                  Generate new ID
                </button>
              </div>
            </div>
            <input
              id="external-id-input"
              type="text"
              value={externalId}
              onChange={(e) => {
                setExternalId(e.target.value);
                if (localError) setLocalError("");
                if (verifyData) setVerifyData(null);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 sm:py-2 text-base sm:text-xs text-teal-300 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 transition-colors font-mono"
            />
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Use this exact value in your IAM role&apos;s <code className="text-slate-400">sts:ExternalId</code> trust condition for confused-deputy protection (or enter an existing External ID if your role is already created).
            </p>
          </div>

          {/* IAM Role Setup Guide (Collapsible) */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5">
            <button
              type="button"
              onClick={() => setShowRoleGuide((prev) => !prev)}
              className="flex items-start sm:items-center justify-between gap-2 w-full text-left text-xs font-medium text-slate-200 hover:text-white cursor-pointer bg-transparent border-none p-0"
            >
              <span className="flex items-start sm:items-center gap-1.5 min-w-0">
                <span className="text-teal-400 shrink-0">2.</span>
                <span>Required IAM Role Trust Policy &amp; Least-Privilege Read-Only Permissions</span>
              </span>
              <span className="text-slate-500 text-[11px] shrink-0 pt-0.5 sm:pt-0">{showRoleGuide ? "Hide ▲" : "Show ▼"}</span>
            </button>

            {showRoleGuide && (
              <div className="mt-3 pt-3 border-t border-slate-800 text-xs space-y-3">
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  In <strong className="text-slate-200">AWS IAM → Roles → Create role</strong>, select{" "}
                  <strong className="text-slate-200">AWS account (Another AWS account)</strong> and enable{" "}
                  <strong className="text-slate-200">Require external ID</strong> with:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
                  <div className="flex items-center justify-between gap-2 bg-slate-950 px-3 py-2 sm:py-1.5 rounded border border-slate-800 min-w-0">
                    <span className="text-slate-500 shrink-0">Account ID:</span>
                    <button
                      type="button"
                      onClick={() => handleCopy("acct", appAccountId)}
                      className="text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0 truncate"
                    >
                      {copiedKey === "acct" ? "Copied ✓" : appAccountId}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2 bg-slate-950 px-3 py-2 sm:py-1.5 rounded border border-slate-800 min-w-0">
                    <span className="text-slate-500 shrink-0">External ID:</span>
                    <span className="text-teal-400 truncate" title={effectiveExternalId}>
                      {effectiveExternalId}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                    <span className="text-[11px] text-slate-400">
                      Attach this exact 36-action read-only inline policy (zero write/delete/billing actions):
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy("policy", IAM_POLICY_JSON)}
                      className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0 shrink-0"
                    >
                      {copiedKey === "policy" ? "Copied ✓" : "Copy Policy JSON"}
                    </button>
                  </div>
                  <pre className="text-[10px] text-slate-300 p-2.5 overflow-x-auto max-h-40 font-mono leading-relaxed bg-slate-950 rounded border border-slate-800">
                    {IAM_POLICY_JSON}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Role ARN Input + Verify Account */}
          <div className="space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <label htmlFor="role-arn-input" className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                3. Enter IAM Role ARN
              </label>
              <button
                type="button"
                onClick={handleVerify}
                disabled={isVerifying || !roleArn.trim()}
                className={`w-full sm:w-auto justify-center text-xs font-medium px-3 py-2 sm:py-1 rounded-lg sm:rounded transition-colors flex items-center gap-1.5 min-h-[38px] sm:min-h-[30px] ${
                  isVerifying || !roleArn.trim()
                    ? "text-slate-600 bg-slate-800/40 cursor-not-allowed"
                    : "text-teal-400 hover:text-teal-300 bg-teal-500/10 border border-teal-500/20 cursor-pointer"
                }`}
              >
                {isVerifying ? (
                  <>
                    <svg className="animate-spin w-3 h-3 text-teal-400" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                    </svg>
                    <span>Verifying…</span>
                  </>
                ) : (
                  <>
                    <span>⚡</span> Verify Account &amp; Permissions
                  </>
                )}
              </button>
            </div>

            <input
              id="role-arn-input"
              type="text"
              value={roleArn}
              onChange={(e) => {
                setRoleArn(e.target.value);
                if (localError) setLocalError("");
                if (scanError) setScanError("");
                if (verifyData) setVerifyData(null);
                if (verifyError) setVerifyError(null);
              }}
              placeholder="arn:aws:iam::123456789012:role/AWSClarityReadOnly"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-base sm:text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 focus:ring-1 focus:ring-teal-500/30 transition-colors font-mono"
            />
          </div>

          {/* Account Verification & 10-Service Permission Check Output */}
          {verifyError && (
            <div className="flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30">
              <span className="text-red-400 font-bold shrink-0">⚠</span>
              <span>{verifyError}</span>
            </div>
          )}

          {verifyData && (
            <div className="rounded-lg bg-slate-950 border border-teal-500/30 p-3.5 space-y-2.5 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold">✓</span>
                  <span className="font-semibold text-slate-100">
                    Identity Verified: Account <span className="font-mono text-teal-300">{verifyData.account_id}</span>
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  {verifyData.enabled_regions?.length || 0} enabled regions detected
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                {SUPPORTED_SERVICES.map((svc) => {
                  const info = verifyData.permission_checks?.[svc];
                  const isOk = info?.status === "PASSED";
                  return (
                    <div key={svc} className="flex items-center gap-1.5 text-[11px] min-w-0">
                      <span className={isOk ? "text-emerald-400 font-bold shrink-0" : "text-orange-400 font-bold shrink-0"}>
                        {isOk ? "✓" : "⚠"}
                      </span>
                      <span className="text-slate-300 truncate">{svc}</span>
                    </div>
                  );
                })}
              </div>

              {Object.values(verifyData.permission_checks || {}).some((i) => i.status !== "PASSED") && (
                <div className="pt-2 border-t border-slate-800 text-[11px] space-y-1.5 break-words">
                  {Object.values(verifyData.permission_checks || {})
                    .filter((i) => i.status !== "PASSED")
                    .map((i) => (
                      <p key={i.service} className="text-orange-300 leading-relaxed">
                        <span className="font-semibold">⚠ {i.service}:</span> Missing{" "}
                        <code className="font-mono text-[10px] bg-orange-950/60 px-1 py-0.5 rounded break-all">
                          {i.required_permission}
                        </code>
                      </p>
                    ))}
                </div>
              )}
            </div>
          )}

          {activeError && (
            <div className="flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30 break-words">
              <span className="text-red-400 font-bold shrink-0">⚠</span>
              <span className="min-w-0">{activeError}</span>
            </div>
          )}

          {/* Start Scan CTA */}
          <div className="pt-1 space-y-2">
            <button
              type="submit"
              className="w-full min-h-[44px] flex items-center justify-center gap-2 bg-teal-600 hover:bg-teal-500 text-white text-sm font-semibold py-2.5 px-4 rounded-lg transition-colors shadow-lg shadow-teal-500/10 cursor-pointer"
            >
              <span>Connect &amp; Scan All Enabled Regions</span>
              <svg className="shrink-0" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
            <p className="text-[11px] text-slate-500 text-center leading-relaxed">
              Discovers all enabled AWS regions automatically · Read-only STS session · Zero modifications
            </p>
          </div>
        </form>

        {/* FAQ */}
        <div className="px-1 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Frequently Asked Questions
          </p>
          {FAQ_ITEMS.map((item, index) => (
            <div key={index} className="border-b border-slate-800/80 last:border-b-0">
              <button
                type="button"
                onClick={() => setOpenFaq((prev) => (prev === index ? null : index))}
                className="w-full min-h-[44px] flex items-center justify-between gap-3 py-2.5 text-left cursor-pointer bg-transparent border-none"
              >
                <span className="text-xs sm:text-[13px] text-slate-400 hover:text-slate-200 transition-colors font-medium">
                  {item.question}
                </span>
                <span className="text-slate-500 text-sm shrink-0">{openFaq === index ? "−" : "+"}</span>
              </button>
              {openFaq === index && (
                <p className="text-xs text-slate-500 pb-3 leading-relaxed">{item.answer}</p>
              )}
            </div>
          ))}
        </div>

        {/* Footer */}
        <footer className="pt-4 border-t border-slate-800/60 flex flex-col items-center gap-2 text-xs text-slate-500">
          <div className="flex items-center gap-2 flex-wrap justify-center">
            <span>Built by</span>
            <a
              href="https://www.linkedin.com/in/david-danso/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-teal-400 transition-colors font-medium"
            >
              David Danso
            </a>
            <span>·</span>
            <span>AWS Cloud Engineer</span>
            <span>·</span>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-teal-400 hover:text-teal-300 transition-colors font-medium bg-transparent border-none p-0 cursor-pointer"
            >
              Trust &amp; Security Architecture
            </button>
          </div>
          <p className="text-[11px] text-slate-600 text-center">
            Strictly read-only · 10 supported AWS services · Zero paid AWS APIs
          </p>
        </footer>
      </div>

      <TrustModal isOpen={trustModalOpen} onClose={() => setTrustModalOpen(false)} />
    </div>
  );
}
