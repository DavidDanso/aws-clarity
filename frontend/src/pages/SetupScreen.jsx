import { useEffect, useState } from "react";
import {
  maskAccountId,
  validateExternalId,
  validateRoleArn,
} from "../utils/formatters";
import {
  IAM_POLICY_JSON,
  PERMISSION_PREVIEW_GROUPS,
  SERVICE_COVERAGE_MATRIX,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import {
  buildCloudFormationTemplate,
  downloadCloudFormationTemplate,
} from "../utils/cloudformationTemplate";
import {
  extractAccountIdFromArn,
  getStableExternalId,
  regenerateStableExternalId,
  saveConnectionDetails,
} from "../utils/connectionStorage";
import { checkPermissions } from "../services/api";
import TrustModal from "../components/TrustModal";

const FAQ_ITEMS = [
  {
    question: "Is AWS Clarity safe to connect to a real AWS account?",
    answer:
      "Yes. AWS Clarity assumes a strictly read-only IAM role that you create, using temporary 1-hour AWS STS credentials and your unique External ID. It has zero permissions to create, modify, stop, or delete any AWS resources.",
  },
  {
    question: "Does AWS Clarity scan every AWS service?",
    answer:
      "No. v1 intentionally supports 10 core services (17 resource types): EC2, VPC, S3, IAM, Lambda, RDS, DynamoDB, EBS, CloudWatch, and CloudTrail across all enabled regions. Services outside those 10 are clearly marked as unsupported in Scan Coverage.",
  },
  {
    question: "Is AWS Clarity free to use?",
    answer:
      "Yes—AWS Clarity is free to use during early access with no subscription, no credit card, and no paid AI or scanning fees. Your own AWS infrastructure charges remain your responsibility, and AWS Clarity never creates billable resources in your account.",
  },
  {
    question: "What happens if my role is missing a permission or a region fails?",
    answer:
      "AWS Clarity never hides errors or displays a 100/100 score on partial results. The scan is marked INCOMPLETE, the health score is withheld until complete, and Scan Coverage lists every affected service, region, reason, and missing IAM permission.",
  },
  {
    question: "How do I disconnect and revoke access?",
    answer:
      "Clear your local browser data in Trust & Privacy Centre, and delete the CloudFormation stack or IAM role in your AWS account. AWS immediately blocks all future sts:AssumeRole requests.",
  },
];

export default function SetupScreen({
  onScanStart,
  onExploreDemo,
  onResumeSession = null,
  resumableAccountId = "",
  initialRoleArn = "",
  initialExternalId = "",
  connectionResetSeq = 0,
  scanError,
  setScanError,
  dataControls = null,
}) {
  const [roleArn, setRoleArn] = useState(initialRoleArn);
  const [externalId, setExternalId] = useState(
    () => initialExternalId || getStableExternalId(initialRoleArn)
  );
  const [localError, setLocalError] = useState("");
  const [copiedKey, setCopiedKey] = useState(null);
  const [openFaq, setOpenFaq] = useState(null);
  const [showMatrix, setShowMatrix] = useState(false);
  const [showPermissionPreview, setShowPermissionPreview] = useState(false);
  const [showPolicyJson, setShowPolicyJson] = useState(false);
  const [setupMethod, setSetupMethod] = useState("cloudformation"); // "cloudformation" | "manual"
  const [showCfnYaml, setShowCfnYaml] = useState(false);
  const [confirmRegenerate, setConfirmRegenerate] = useState(false);
  const [externalIdNotice, setExternalIdNotice] = useState("");

  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyData, setVerifyData] = useState(null);
  const [verifyError, setVerifyError] = useState(null);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  // Sync local form state whenever Data Controls forgets/clears saved connection details
  useEffect(() => {
    if (connectionResetSeq === 0) return;
    setRoleArn(initialRoleArn);
    setExternalId(initialExternalId || getStableExternalId(""));
    setVerifyData(null);
    setVerifyError(null);
    setConfirmRegenerate(false);
    setExternalIdNotice(
      "Saved connection details were removed from this browser (your AWS IAM role was NOT modified). A fresh External ID was generated for new roles. If you already created an IAM role in AWS, paste its existing sts:ExternalId from AWS IAM → Roles → Trust relationships above."
    );
  }, [connectionResetSeq, initialRoleArn, initialExternalId]);

  const effectiveExternalId = externalId.trim();
  const appAccountId = import.meta.env.VITE_APP_ACCOUNT_ID || "Set VITE_APP_ACCOUNT_ID";

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

    saveConnectionDetails(roleArn.trim(), effectiveExternalId);
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
    saveConnectionDetails(roleArn.trim(), effectiveExternalId);
    onScanStart(roleArn.trim(), effectiveExternalId);
  };

  const handleRoleArnChange = (nextArn) => {
    setRoleArn(nextArn);
    if (localError) setLocalError("");
    if (scanError) setScanError("");
    if (verifyData) setVerifyData(null);
    if (verifyError) setVerifyError(null);

    // If the user enters an AWS account ID we already have a saved stable External ID for, restore it
    const acct = extractAccountIdFromArn(nextArn);
    if (acct) {
      const savedForAcct = getStableExternalId(nextArn);
      if (savedForAcct && savedForAcct !== externalId) {
        setExternalId(savedForAcct);
      }
    }
  };

  const activeError = localError || scanError;
  const cfnYaml = buildCloudFormationTemplate({ appAccountId, externalId: effectiveExternalId });
  const missingPermEntries = Object.values(verifyData?.permission_checks || {}).filter(
    (i) => i.status !== "PASSED"
  );

  return (
    <div className="min-h-[100dvh] bg-slate-950 flex flex-col items-center justify-start px-3.5 sm:px-6 lg:px-8 py-6 sm:py-10 lg:py-12 pb-20 sm:pb-16 text-slate-100">
      <div className="w-full max-w-2xl lg:max-w-3xl flex flex-col space-y-6 sm:space-y-7">
        {/* Top Navigation Strip */}
        <div className="flex items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2 text-xs font-semibold text-slate-200">
            <span className="w-6 h-6 rounded-md bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400">
              <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            <span>AWS Clarity</span>
          </div>
          <button
            type="button"
            onClick={() => setTrustModalOpen(true)}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
            <span>Trust &amp; Privacy Centre</span>
          </button>
        </div>

        {/* Hero */}
        <header className="flex flex-col items-center text-center space-y-3.5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-[11px] sm:text-xs font-medium max-w-full">
            <span className="truncate">Read-Only AWS Visibility · Free Early Access · No Credit Card</span>
          </div>
          <h1 className="text-xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight max-w-2xl leading-tight">
            Understand Your AWS Account Without Guesswork or Write Access
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl leading-relaxed">
            Inspect your real AWS inventory across <strong>10 core services</strong> and all enabled regions. Surface
            security risks, operational concerns, and potential cost waste with exact AWS API evidence and safe manual fix steps.
          </p>

          {/* Explore Demo CTA */}
          {onExploreDemo && (
            <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1 w-full sm:w-auto">
              <button
                type="button"
                onClick={onExploreDemo}
                className="w-full sm:w-auto min-h-[42px] px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-teal-500/40 text-teal-300 hover:text-teal-200 text-xs sm:text-sm font-semibold transition-colors cursor-pointer flex items-center justify-center gap-2"
              >
                <span>Explore Demo</span>
                <span className="text-[11px] font-normal text-slate-400">(No AWS account needed)</span>
              </button>
              <a
                href="#connect-form"
                className="w-full sm:w-auto min-h-[42px] px-4 py-2.5 rounded-lg border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs sm:text-sm font-medium transition-colors flex items-center justify-center"
              >
                Connect Your AWS Account ↓
              </a>
            </div>
          )}
        </header>

        {/* Resume Current Tab Scan */}
        {onResumeSession && (
          <div className="rounded-xl border border-teal-500/30 bg-teal-950/20 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs">
            <span className="text-teal-200">
              You have an active scan in this browser tab for{" "}
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
                10 Supported AWS Services · 17 Resource Types (v1 Scope)
              </p>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Scans only the 10 services below across enabled regions—other AWS services are explicitly outside v1 scope.
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
                    <div className="sm:col-span-4 text-slate-300">{row.resources.join(", ")}</div>
                    <div className="sm:col-span-5 text-slate-400 leading-relaxed">{row.checks}</div>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-500">
                Not covered in v1: Cost Explorer APIs (paid), GuardDuty/Config/Security Hub (paid), AWS services outside the 10 listed above, and customer data contents.
              </p>
            </div>
          )}
        </section>

        {/* Guided 3-Step Connect Account Form */}
        <form
          id="connect-form"
          onSubmit={handleSubmit}
          className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-6 scroll-mt-6"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-white">Connect Your AWS Account (3 Guided Steps)</h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Free during early access · No subscription or paid AI · Your existing AWS infrastructure charges remain yours.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-xs text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0 shrink-0"
            >
              Trust &amp; Privacy Details →
            </button>
          </div>

          {/* STEP 1 — Review Permissions (Permission Preview) */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-100">
                  <span className="text-teal-400 mr-1.5">Step 1.</span>
                  Review Requested Read-Only Permissions (35 Actions)
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Inspect every permission before creating the role. Zero write, delete, object-listing, or data-read actions.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowPermissionPreview((prev) => !prev)}
                className="text-xs font-medium text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0 shrink-0"
              >
                {showPermissionPreview ? "Hide permission preview ▲" : "Preview all 35 permissions ▼"}
              </button>
            </div>

            {showPermissionPreview && (
              <div className="pt-2 border-t border-slate-800 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                    <div key={grp.service} className="p-2.5 rounded-lg bg-slate-900/70 border border-slate-800/80 space-y-1">
                      <p className="text-[11px] font-semibold text-slate-200">{grp.service}</p>
                      <p className="text-[10px] text-slate-400 leading-relaxed">{grp.summary}</p>
                      <p className="text-[10px] font-mono text-slate-500 break-all">
                        {grp.actions.join(", ")}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2">
                  <button
                    type="button"
                    onClick={() => setShowPolicyJson((prev) => !prev)}
                    className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
                  >
                    {showPolicyJson ? "Hide raw JSON policy ▲" : "View raw JSON policy ▼"}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleCopy("policy", IAM_POLICY_JSON)}
                    className="text-[11px] text-slate-300 hover:text-white font-medium cursor-pointer bg-slate-800/70 border border-slate-700 px-2.5 py-1 rounded"
                  >
                    {copiedKey === "policy" ? "Copied Policy JSON ✓" : "Copy Policy JSON"}
                  </button>
                </div>

                {showPolicyJson && (
                  <pre className="text-[10px] text-slate-300 p-2.5 overflow-x-auto max-h-44 font-mono leading-relaxed bg-slate-950 rounded border border-slate-800">
                    {IAM_POLICY_JSON}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* STEP 2 — Create the Read-Only IAM Role (CloudFormation or Manual) */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-100">
                <span className="text-teal-400 mr-1.5">Step 2.</span>
                Create the Read-Only IAM Role in Your AWS Account
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                AWS Clarity never deploys into your account automatically. Download and review the CloudFormation template
                or create the role manually in AWS IAM.
              </p>
            </div>

            {/* Stable Per-Connection External ID */}
            <div className="space-y-1.5">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-2">
                <label htmlFor="external-id-input" className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Connection External ID (Stable per account)
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
                      saveConnectionDetails(roleArn, "aws-clarity-scan");
                      setVerifyData(null);
                      setConfirmRegenerate(false);
                      setExternalIdNotice(
                        "Switched to legacy value 'aws-clarity-scan'. Only use this if your existing IAM role already trusts it—for new roles, prefer a unique random External ID."
                      );
                    }}
                    className="text-[11px] text-slate-400 hover:text-slate-200 font-medium cursor-pointer bg-transparent border-none py-0.5 px-0"
                  >
                    Use legacy default
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setConfirmRegenerate((prev) => !prev);
                    }}
                    className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none py-0.5 px-0"
                  >
                    Regenerate ID
                  </button>
                </div>
              </div>
              <input
                id="external-id-input"
                type="text"
                value={externalId}
                onChange={(e) => {
                  const next = e.target.value;
                  setExternalId(next);
                  saveConnectionDetails(roleArn, next);
                  if (localError) setLocalError("");
                  if (verifyData) setVerifyData(null);
                  if (confirmRegenerate) setConfirmRegenerate(false);
                  if (externalIdNotice) setExternalIdNotice("");
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 sm:py-2 text-base sm:text-xs text-teal-300 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 transition-colors font-mono"
              />

              {confirmRegenerate && (
                <div className="p-2.5 rounded-lg bg-amber-950/35 border border-amber-500/40 text-[11px] text-amber-200 space-y-2">
                  <p className="leading-relaxed">
                    <strong>Warning:</strong> Generating a new External ID will break any existing IAM role that still
                    trusts <code className="font-mono text-amber-100">{effectiveExternalId}</code>. You must also update{" "}
                    <code className="font-mono text-amber-100">sts:ExternalId</code> in your IAM role&apos;s{" "}
                    <strong>Trust relationships</strong> tab (or update your CloudFormation stack) to match the new value.
                  </p>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const fresh = regenerateStableExternalId(roleArn);
                        setExternalId(fresh);
                        setVerifyData(null);
                        setConfirmRegenerate(false);
                        setExternalIdNotice(
                          "Generated a new External ID. Remember to update sts:ExternalId in your IAM role's Trust relationships tab (or re-upload the CloudFormation template) before scanning."
                        );
                      }}
                      className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-100 font-semibold cursor-pointer"
                    >
                      Confirm Regenerate ID
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmRegenerate(false)}
                      className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {externalIdNotice && (
                <div className="p-2.5 rounded-lg bg-sky-950/35 border border-sky-500/30 text-[11px] text-sky-200 leading-relaxed flex items-start justify-between gap-2">
                  <span>{externalIdNotice}</span>
                  <button
                    type="button"
                    onClick={() => setExternalIdNotice("")}
                    className="text-sky-300 hover:text-white shrink-0 bg-transparent border-none p-0 cursor-pointer"
                    aria-label="Dismiss External ID notice"
                  >
                    ✕
                  </button>
                </div>
              )}

              <p className="text-[11px] text-slate-500 leading-relaxed">
                Saved stably across sessions in this browser for your account connection. An External ID provides{" "}
                <strong className="text-slate-400">confused-deputy protection</strong>—it is <strong>not</strong> an AWS
                password or authentication credential. Avoid predictable values (like <code className="text-slate-400">aws-clarity-scan</code>) on real accounts.
              </p>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                <strong className="text-slate-400">Already created a role or cleared browser storage?</strong> You do not
                need to guess—open <strong>AWS IAM → Roles → [Your Role] → Trust relationships</strong>, copy the{" "}
                <code className="text-slate-400">sts:ExternalId</code> value shown there, and paste it above.
              </p>
            </div>

            {/* Setup Method Switcher: CloudFormation vs Manual */}
            <div className="flex items-center gap-1.5 border-b border-slate-800 pb-2.5">
              <button
                type="button"
                onClick={() => setSetupMethod("cloudformation")}
                className={`text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors cursor-pointer ${
                  setupMethod === "cloudformation"
                    ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
                    : "bg-transparent border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                CloudFormation Template (Recommended)
              </button>
              <button
                type="button"
                onClick={() => setSetupMethod("manual")}
                className={`text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors cursor-pointer ${
                  setupMethod === "manual"
                    ? "bg-teal-500/15 border-teal-500/40 text-teal-300"
                    : "bg-transparent border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                Manual IAM Console
              </button>
            </div>

            {setupMethod === "cloudformation" ? (
              <div className="space-y-3 text-xs">
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Creates <strong>only one</strong> read-only <code className="text-slate-300">AWS::IAM::Role</code> with
                  the exact 35 read-only actions above, pre-configured with App Account ID{" "}
                  <code className="text-teal-300">{appAccountId}</code> and your External ID. Creates zero chargeable resources.
                </p>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      downloadCloudFormationTemplate({
                        appAccountId,
                        externalId: effectiveExternalId,
                      })
                    }
                    className="px-3.5 py-2 rounded-lg bg-teal-600/20 hover:bg-teal-600/30 border border-teal-500/40 text-teal-300 text-xs font-semibold cursor-pointer transition-colors"
                  >
                    Download CloudFormation YAML
                  </button>
                  <button
                    type="button"
                    onClick={() => handleCopy("cfn", cfnYaml)}
                    className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-medium cursor-pointer transition-colors"
                  >
                    {copiedKey === "cfn" ? "Copied YAML ✓" : "Copy YAML"}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowCfnYaml((prev) => !prev)}
                    className="text-xs text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none px-1 py-1"
                  >
                    {showCfnYaml ? "Hide template ▲" : "Inspect template ▼"}
                  </button>
                </div>

                {showCfnYaml && (
                  <pre className="text-[10px] text-slate-300 p-3 overflow-x-auto max-h-52 font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800">
                    {cfnYaml}
                  </pre>
                )}

                <ol className="list-decimal pl-4 space-y-1 text-[11px] text-slate-400">
                  <li>Open <strong>AWS CloudFormation → Stacks → Create stack (With new resources)</strong>.</li>
                  <li>Choose <strong>Upload a template file</strong> and select <code className="text-slate-300">aws-clarity-readonly-role.yaml</code>.</li>
                  <li>Review the parameters (Account ID &amp; External ID are pre-filled), acknowledge IAM resource creation, and click <strong>Submit</strong>.</li>
                  <li>Open the stack&apos;s <strong>Outputs</strong> tab, copy <code className="text-teal-300">RoleArn</code>, and paste it in Step 3 below.</li>
                </ol>
              </div>
            ) : (
              <div className="space-y-3 text-xs">
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
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-400">
                    Attach the exact 35-action read-only inline policy from Step 1:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy("policy-manual", IAM_POLICY_JSON)}
                    className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0 shrink-0"
                  >
                    {copiedKey === "policy-manual" ? "Copied ✓" : "Copy Policy JSON"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* STEP 3 — Verify Connection & Start Scan */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <label htmlFor="role-arn-input" className="text-xs font-semibold text-slate-100">
                <span className="text-teal-400 mr-1.5">Step 3.</span>
                Paste Your IAM Role ARN &amp; Verify Connection
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
              onChange={(e) => handleRoleArnChange(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/AWSClarityReadOnly"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-base sm:text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 focus:ring-1 focus:ring-teal-500/30 transition-colors font-mono"
            />
          </div>

          {/* Account Verification & 10-Service Permission Check Output */}
          {verifyError && (
            <div className="border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30 break-words space-y-1">
              <div className="flex items-start gap-2">
                <span className="text-red-400 font-bold shrink-0">⚠</span>
                <span className="min-w-0">{verifyError}</span>
              </div>
              {/assume|external/i.test(verifyError) && (
                <p className="text-[11px] text-red-200/80 pl-5 leading-relaxed">
                  Recovery tip: Open <strong>AWS IAM → Roles → [Your Role] → Trust relationships</strong> and confirm
                  the <code className="font-mono">sts:ExternalId</code> matches Step 2 above (especially if you cleared
                  browser storage or regenerated your External ID).
                </p>
              )}
            </div>
          )}

          {verifyData && (
            <div className="rounded-lg bg-slate-950 border border-teal-500/30 p-3.5 space-y-2.5 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold">✓</span>
                  <span className="font-semibold text-slate-100">
                    Role Assumed: Account <span className="font-mono text-teal-300">{verifyData.account_id}</span>
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  {verifyData.enabled_regions?.length || 0} enabled regions detected
                </span>
              </div>

              {verifyData.region_discovery?.status === "INCOMPLETE" && (
                <p className="text-[11px] text-orange-300 bg-orange-950/30 border border-orange-500/30 rounded px-2.5 py-1.5">
                  ⚠ {verifyData.region_discovery.reason}
                </p>
              )}

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

              {missingPermEntries.length > 0 && (
                <div className="pt-2 border-t border-slate-800 text-[11px] space-y-1.5 break-words">
                  <p className="text-orange-200 font-medium">
                    Missing permissions will mark scan coverage as INCOMPLETE and withhold the account health score:
                  </p>
                  {missingPermEntries.map((i) => (
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
              Strictly read-only · Temporary 1-hour STS session · Zero modifications to your AWS account
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
              Trust &amp; Privacy Centre
            </button>
          </div>
          <p className="text-[11px] text-slate-600 text-center">
            Free early access · Strictly read-only · 10 supported AWS services · No paid scanning APIs
          </p>
        </footer>
      </div>

      <TrustModal
        isOpen={trustModalOpen}
        onClose={() => setTrustModalOpen(false)}
        dataControls={dataControls}
      />
    </div>
  );
}
