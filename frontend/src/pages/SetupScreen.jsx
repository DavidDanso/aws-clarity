import { useState } from "react";
import {
  generateExternalId,
  validateExternalId,
  validateRoleArn,
} from "../utils/formatters";
import {
  DEFAULT_EXTERNAL_ID,
  IAM_POLICY_JSON,
  SUPPORTED_REGIONS,
  SUPPORTED_SERVICES_OVERVIEW,
} from "../utils/constants";
import { checkPermissions } from "../services/api";
import TrustModal from "../components/TrustModal";

const FAQ_ITEMS = [
  {
    question: "Is AWS Clarity safe to connect?",
    answer:
      "Yes. AWS Clarity uses a strictly read-only IAM role temporarily assumed via AWS STS for 1 hour. It has zero permissions to create, modify, stop, or delete any resources.",
  },
  {
    question: "Does AWS Clarity ask for AWS passwords or access keys?",
    answer:
      "Never. Authentication uses temporary cross-account STS credentials via your IAM Role ARN and External ID—no root passwords or permanent access keys are ever requested.",
  },
  {
    question: "Will scanning my account create AWS charges?",
    answer:
      "AWS Clarity avoids paid AWS APIs completely (zero Cost Explorer, AWS Config, GuardDuty, or Security Hub calls). All Describe/List/Get inspection calls use free control-plane APIs, plus 1 lightweight S3 ListObjectsV2 call per bucket.",
  },
  {
    question: "Why does AWS Clarity focus on 7 core services instead of all 200+?",
    answer:
      "Keeping v1 focused on the most commonly used services (EC2/EBS, VPC/ELB, S3, RDS, DynamoDB, Lambda, IAM) ensures scans stay fast, accurate, zero-cost, and completely transparent about what is and isn't checked.",
  },
  {
    question: "What happens if a permission is missing?",
    answer:
      "AWS Clarity runs a partial scan. It inspects the services your role permits, marks the scan as partial, and explicitly lists which checks could not be assessed instead of guessing.",
  },
  {
    question: "How do I revoke access?",
    answer:
      "Delete the IAM role or edit its trust policy in your AWS Console at any time. AWS immediately rejects all subsequent assume-role requests.",
  },
];

export default function SetupScreen({
  onScanStart,
  initialRoleArn = "",
  initialExternalId = DEFAULT_EXTERNAL_ID,
  initialRegion = "us-east-1",
  scanError,
  setScanError,
}) {
  const [roleArn, setRoleArn] = useState(initialRoleArn);
  const [externalId, setExternalId] = useState(initialExternalId || DEFAULT_EXTERNAL_ID);
  const [selectedRegion, setSelectedRegion] = useState(initialRegion || "us-east-1");
  const [localError, setLocalError] = useState("");
  const [copiedPolicy, setCopiedPolicy] = useState(false);
  const [openFaq, setOpenFaq] = useState(null);
  const [showRoleGuide, setShowRoleGuide] = useState(false);
  const [showScope, setShowScope] = useState(false);

  const [isPrechecking, setIsPrechecking] = useState(false);
  const [precheckResults, setPrecheckResults] = useState(null);
  const [precheckError, setPrecheckError] = useState(null);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  const effectiveExternalId = externalId.trim() || DEFAULT_EXTERNAL_ID;

  const handleCopyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(IAM_POLICY_JSON);
      setCopiedPolicy(true);
      setTimeout(() => setCopiedPolicy(false), 2000);
    } catch {
      // Ignore clipboard failures
    }
  };

  const validateInputs = () => {
    if (!roleArn.trim()) {
      setLocalError("Role ARN is required.");
      return false;
    }
    if (!validateRoleArn(roleArn.trim())) {
      setLocalError("Invalid Role ARN format. Expected: arn:aws:iam::123456789012:role/RoleName");
      return false;
    }
    if (!validateExternalId(effectiveExternalId)) {
      setLocalError("External ID must be 2–128 characters using letters, numbers, or +=,.@:/_-");
      return false;
    }
    return true;
  };

  const handlePrecheck = async () => {
    setLocalError("");
    setScanError("");
    setPrecheckError(null);
    if (!validateInputs()) return;

    setIsPrechecking(true);
    try {
      const resp = await checkPermissions(roleArn.trim(), effectiveExternalId);
      setPrecheckResults(resp.permission_checks || {});
    } catch (err) {
      setPrecheckError(err.message || "Failed to test role permissions.");
    } finally {
      setIsPrechecking(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setLocalError("");
    setScanError("");
    if (!validateInputs()) return;

    if (!selectedRegion) {
      setLocalError("Please select a region to scan.");
      return;
    }

    onScanStart(roleArn.trim(), [selectedRegion], effectiveExternalId);
  };

  const activeError = localError || scanError;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-start px-4 py-8 sm:py-12 text-slate-100">
      <div className="w-full max-w-xl flex flex-col space-y-7">
        {/* Header */}
        <header className="flex flex-col items-center text-center">
          <div className="flex items-center gap-2 mb-2.5">
            <div className="w-7 h-7 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="text-base font-semibold text-white tracking-tight">AWS Clarity</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            One Central View of Your AWS Account
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1.5 max-w-md leading-relaxed">
            Search resources, uncover security misconfigurations, and spot unused or bill-generating infrastructure—strictly read-only and free to run.
          </p>
        </header>

        {/* Trust & Read-Only Guarantees */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 space-y-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Security & Trust Guarantees
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="flex items-start gap-2">
              <span className="text-teal-400 font-bold">✓</span>
              <div>
                <span className="font-medium text-slate-200">Strictly Read-Only</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  25 least-privilege Describe/List/Get actions. Cannot modify or delete resources.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 font-bold">✓</span>
              <div>
                <span className="font-medium text-slate-200">Temporary STS + External ID</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  1-hour STS session with confused-deputy External ID protection. No keys stored.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 font-bold">✓</span>
              <div>
                <span className="font-medium text-slate-200">Deterministic Accuracy</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  37 deterministic rules with observed evidence and explicit unassessed states.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 font-bold">✓</span>
              <div>
                <span className="font-medium text-slate-200">Zero Paid AWS APIs</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  No Cost Explorer, GuardDuty, or Config calls. Detects waste from metadata alone.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Connect Form Card */}
        <form onSubmit={handleSubmit} className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-5">
          {/* Collapsible Supported Scope */}
          <div className="border-b border-slate-800/80 pb-3.5">
            <button
              type="button"
              onClick={() => setShowScope((prev) => !prev)}
              className="flex items-center justify-between w-full text-xs font-medium text-slate-300 hover:text-white py-0.5 transition-colors cursor-pointer bg-transparent border-none"
            >
              <span className="flex items-center gap-1.5">
                <span className="text-teal-400">◈</span>
                <span>Supported scope: 7 core AWS services (14 resource types)</span>
              </span>
              <span className="text-slate-500 text-[11px]">{showScope ? "Hide ▲" : "View ▼"}</span>
            </button>

            {showScope && (
              <div className="mt-3 space-y-2 text-[11px]">
                {SUPPORTED_SERVICES_OVERVIEW.map((item) => (
                  <div key={item.service} className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-teal-300">{item.service}</span>
                      <span className="text-slate-400 text-[10px]">{item.resources}</span>
                    </div>
                    <p className="text-slate-400 mt-0.5 leading-relaxed">{item.focus}</p>
                  </div>
                ))}
                <p className="text-[10px] text-slate-500 pt-1">
                  Out of scope in v1: Cost Explorer, CloudTrail logs, GuardDuty, EKS/ECS/Redshift, and S3/DB data contents.
                </p>
              </div>
            )}
          </div>

          {/* Collapsible IAM Role Setup Guide */}
          <div className="border-b border-slate-800/80 pb-3.5">
            <button
              type="button"
              onClick={() => setShowRoleGuide((prev) => !prev)}
              className="flex items-center justify-between w-full text-xs font-medium text-slate-300 hover:text-white py-0.5 transition-colors cursor-pointer bg-transparent border-none"
            >
              <span className="flex items-center gap-1.5">
                <span className="text-teal-400">ℹ</span>
                <span>Need to create the read-only IAM role? View setup steps</span>
              </span>
              <span className="text-slate-500 text-[11px]">{showRoleGuide ? "Hide ▲" : "Show ▼"}</span>
            </button>

            {showRoleGuide && (
              <div className="mt-3 pt-3 border-t border-slate-800 text-xs space-y-3">
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  1. In AWS IAM → Roles → Create role, choose{" "}
                  <strong className="text-slate-200">AWS account (Another AWS account)</strong> and enable{" "}
                  <strong className="text-slate-200">Require external ID</strong>:
                </p>
                <div className="space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                    <span className="text-slate-500">App Account ID:</span>
                    <span className="text-teal-400">{import.meta.env.VITE_APP_ACCOUNT_ID || "Set VITE_APP_ACCOUNT_ID"}</span>
                  </div>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                    <span className="text-slate-500">External ID:</span>
                    <span className="text-teal-400">{effectiveExternalId}</span>
                  </div>
                </div>
                <div className="pt-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] text-slate-400">
                      2. Attach this exact 25-action read-only inline policy:
                    </span>
                    <button
                      type="button"
                      onClick={handleCopyPolicy}
                      className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
                    >
                      {copiedPolicy ? "Copied ✓" : "Copy Policy JSON"}
                    </button>
                  </div>
                  <pre className="text-[10px] text-slate-300 p-2.5 overflow-x-auto max-h-40 font-mono leading-relaxed bg-slate-950 rounded border border-slate-800">
                    {IAM_POLICY_JSON}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Role ARN Input + Precheck */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label htmlFor="role-arn-input" className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                IAM Role ARN
              </label>
              <button
                type="button"
                onClick={handlePrecheck}
                disabled={isPrechecking || !roleArn.trim()}
                className={`text-xs font-medium px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                  isPrechecking || !roleArn.trim()
                    ? "text-slate-600 bg-slate-800/40 cursor-not-allowed"
                    : "text-teal-400 hover:text-teal-300 bg-teal-500/10 border border-teal-500/20 cursor-pointer"
                }`}
              >
                {isPrechecking ? (
                  <>
                    <svg className="animate-spin w-3 h-3 text-teal-400" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                    </svg>
                    <span>Testing...</span>
                  </>
                ) : (
                  <>
                    <span>⚡</span> Test Permissions
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
                if (precheckResults) setPrecheckResults(null);
                if (precheckError) setPrecheckError(null);
              }}
              placeholder="arn:aws:iam::123456789012:role/AWSClarityReadOnly"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 focus:ring-1 focus:ring-teal-500/30 transition-colors font-mono"
            />
          </div>

          {/* External ID Field (with unique generator for tenant isolation) */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="external-id-input" className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                External ID
              </label>
              <button
                type="button"
                onClick={() => {
                  setExternalId(generateExternalId());
                  if (precheckResults) setPrecheckResults(null);
                }}
                className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
              >
                Generate unique ID
              </button>
            </div>
            <input
              id="external-id-input"
              type="text"
              value={externalId}
              onChange={(e) => {
                setExternalId(e.target.value);
                if (localError) setLocalError("");
                if (precheckResults) setPrecheckResults(null);
              }}
              placeholder={DEFAULT_EXTERNAL_ID}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-teal-500/60 transition-colors font-mono"
            />
            <p className="text-[11px] text-slate-500">
              Must match the <code className="text-slate-400">sts:ExternalId</code> condition in your role&apos;s trust policy.
            </p>
          </div>

          {/* Precheck Results / Errors */}
          {precheckError && (
            <div className="flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30">
              <span className="text-red-400 font-bold shrink-0">⚠</span>
              <span>{precheckError}</span>
            </div>
          )}

          {precheckResults && (
            <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 space-y-2">
              <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Permission Pre-Check
                </span>
                <span className="text-[10px] text-teal-400 font-mono">Read-Only Verified</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                {Object.entries(precheckResults).map(([svc, info]) => {
                  const isOk = info.status === "PASSED";
                  return (
                    <div key={svc} className="flex items-center gap-1.5 min-w-0">
                      <span className={isOk ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                        {isOk ? "✓" : "⚠"}
                      </span>
                      <span className="text-slate-300 font-medium truncate">{svc}</span>
                      <span className={`text-[10px] px-1 rounded truncate ${
                        isOk ? "text-emerald-400/80 bg-emerald-500/10" : "text-amber-400/80 bg-amber-500/10"
                      }`}>
                        {isOk ? "Ready" : "Missing"}
                      </span>
                    </div>
                  );
                })}
              </div>

              {Object.values(precheckResults).some((info) => info.status !== "PASSED") && (
                <div className="mt-2 pt-2 border-t border-slate-800 text-[11px] space-y-1">
                  {Object.values(precheckResults)
                    .filter((info) => info.status !== "PASSED")
                    .map((info) => (
                      <div key={info.service} className="text-amber-300">
                        <span className="font-semibold">⚠ {info.service}:</span> Requires{" "}
                        <code className="text-[10px] text-amber-200 font-mono bg-amber-950/60 px-1 py-0.5 rounded">
                          {info.required_permission}
                        </code>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}

          {activeError && (
            <div className="flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30">
              <span className="text-red-400 font-bold shrink-0">⚠</span>
              <span>{activeError}</span>
            </div>
          )}

          {/* Region Selection */}
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Region to Scan
            </p>
            <div className="grid grid-cols-2 gap-1 max-h-36 overflow-y-auto pr-1">
              {SUPPORTED_REGIONS.map((region) => (
                <label
                  key={region.id}
                  className={`flex items-center gap-2 text-xs rounded-lg px-2.5 py-1.5 cursor-pointer select-none transition-colors ${
                    selectedRegion === region.id
                      ? "bg-teal-500/10 text-teal-300 border border-teal-500/30"
                      : "text-slate-400 hover:text-slate-200 border border-transparent"
                  }`}
                >
                  <input
                    type="radio"
                    name="region"
                    value={region.id}
                    checked={selectedRegion === region.id}
                    onChange={() => setSelectedRegion(region.id)}
                    className="shrink-0 accent-teal-500"
                  />
                  <span>{region.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Scan Submit */}
          <div className="pt-1">
            <button
              type="submit"
              className="w-full flex items-center justify-center gap-2 bg-teal-600 hover:bg-teal-500 text-white text-sm font-semibold py-2.5 px-4 rounded-lg transition-colors shadow-lg shadow-teal-500/10 cursor-pointer"
            >
              <span>Scan My AWS Account</span>
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          </div>
        </form>

        {/* FAQ Accordion */}
        <div className="px-1 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Frequently Asked Questions
          </p>
          {FAQ_ITEMS.map((item, index) => (
            <div key={index} className="border-b border-slate-800/80 last:border-b-0">
              <button
                type="button"
                onClick={() => setOpenFaq((prev) => (prev === index ? null : index))}
                className="w-full flex items-center justify-between py-2 text-left cursor-pointer bg-transparent border-none"
              >
                <span className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">
                  {item.question}
                </span>
                <span className="text-slate-500 text-xs ml-2">{openFaq === index ? "−" : "+"}</span>
              </button>
              {openFaq === index && (
                <p className="text-xs text-slate-500 pb-2.5 leading-relaxed">{item.answer}</p>
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
              Trust & Security Architecture
            </button>
          </div>
          <p className="text-[11px] text-slate-600 text-center">
            Read-only configuration inspection · Zero customer resources modified · Zero paid AWS APIs
          </p>
        </footer>
      </div>

      <TrustModal isOpen={trustModalOpen} onClose={() => setTrustModalOpen(false)} />
    </div>
  );
}
