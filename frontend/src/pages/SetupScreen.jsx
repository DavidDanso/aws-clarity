import { useRef, useState } from "react";
import { maskAccountId } from "../utils/formatters";
import {
  IAM_POLICY_DEFAULT_JSON,
  IAM_POLICY_JSON,
  PERMISSION_PREVIEW_GROUPS,
  SERVICE_COVERAGE_MATRIX,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import { parseLocalAssessmentReport } from "../utils/reportImporter";
import { downloadLocalFile } from "../utils/reportSanitizer";
import TrustModal from "../components/TrustModal";

const FAQ_ITEMS = [
  {
    question: "Why does AWS Clarity run locally instead of scanning from a vendor server?",
    answer:
      "Because you should not have to grant a third-party backend cross-account access to your AWS environment. Running the open-source CLI on your own computer keeps your AWS credentials and account inventory entirely under your control—and means a compromise of this static website cannot expose stored customer accounts.",
  },
  {
    question: "Does importing my JSON report upload it anywhere?",
    answer:
      "No. Your report file is read and parsed locally in browser memory. The production static site enforces Content-Security-Policy `connect-src 'none'`, blocking outbound network requests from the dashboard, and includes zero analytics or tracking scripts.",
  },
  {
    question: "Will running the local scanner create AWS charges in my account?",
    answer:
      "By default, `aws-clarity scan` checks 9 AWS services using free control-plane Describe/List/Get APIs and skips S3 because S3 bills LIST/GET API requests outside an account's 12-month S3 Free Tier. S3 checks require explicit opt-in (`--include-s3-checks`) with cost disclosure and confirmation.",
  },
  {
    question: "Does AWS Clarity work with IAM Identity Center (AWS SSO) and existing read-only roles?",
    answer:
      "Yes. The local CLI uses the standard AWS SDK credential chain (`--profile`), supporting `aws sso login`, AWS CLI named profiles, temporary STS credentials, and optional customer-owned `--role-arn` role assumption—without ever trusting an AWS Clarity account.",
  },
  {
    question: "Can my team use AWS Clarity without signing up for an account?",
    answer:
      "Yes. Each engineer runs the local CLI with their own authorized AWS profile and can export a full or sanitized (redacted) JSON/CSV report to share via your team's existing secure channels. There is no central database or account registration.",
  },
];

export default function SetupScreen({
  onImportReport,
  onExploreDemo,
  onResumeReport = null,
  resumableAccountId = "",
  importError = "",
  setImportError,
  dataControls = null,
}) {
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const [openFaq, setOpenFaq] = useState(null);
  const [showMatrix, setShowMatrix] = useState(false);
  const [showPermissionPreview, setShowPermissionPreview] = useState(false);
  const [policyVariant, setPolicyVariant] = useState("default"); // "default" (28) | "with-s3" (34)
  const [showPolicyJson, setShowPolicyJson] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  const activePolicyJson =
    policyVariant === "with-s3" ? IAM_POLICY_JSON : IAM_POLICY_DEFAULT_JSON;
  const activePolicyFilename =
    policyVariant === "with-s3"
      ? "aws-clarity-readonly-policy-with-s3.json"
      : "aws-clarity-readonly-policy-default.json";

  const handleCopy = async (key, text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Ignore clipboard failures
    }
  };

  const processSelectedFile = async (file) => {
    if (!file) return;
    if (setImportError) setImportError("");
    try {
      const text = await file.text();
      const parsed = parseLocalAssessmentReport(text, file.size);
      onImportReport(parsed, file.name);
    } catch (err) {
      if (setImportError) {
        setImportError(err.message || "Could not import the selected report file.");
      }
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const handleFileInputChange = (e) => {
    const file = e.target.files?.[0];
    processSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer?.files?.[0];
    processSelectedFile(file);
  };

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
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-500/10 border border-teal-500/25 text-teal-300">
              Local-First
            </span>
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
            <span className="truncate">Free · Local-Only Scanner · Zero Backend Data Collection</span>
          </div>
          <h1 className="text-xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight max-w-2xl leading-tight">
            Your AWS Account. Your Credentials. Your Data. Your Control.
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl leading-relaxed">
            Run the open-source, strictly read-only <code className="text-teal-300">aws-clarity</code> CLI locally using
            your own AWS CLI or IAM Identity Center profile, then inspect the generated JSON report locally in this
            browser. AWS Clarity minimizes what it collects, never stores customer inventories centrally, never modifies
            AWS resources, and requires no payment.
          </p>

          {/* Key Privacy Facts Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 w-full pt-1 text-left">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-0.5">
              <p className="text-[11px] font-semibold text-teal-300">No Central Credentials</p>
              <p className="text-[11px] text-slate-400">Uses your local AWS CLI / SSO session. Never asks for AWS keys or cross-account vendor roles.</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-0.5">
              <p className="text-[11px] font-semibold text-teal-300">No Report Upload</p>
              <p className="text-[11px] text-slate-400">Imported reports are parsed in browser memory only. Static site enforces <code className="text-slate-300">connect-src &apos;none&apos;</code>.</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-0.5">
              <p className="text-[11px] font-semibold text-teal-300">Free &amp; Cost-Conscious</p>
              <p className="text-[11px] text-slate-400">$0 subscription. Default scan uses 9 free control-plane services; S3 checks require explicit opt-in.</p>
            </div>
          </div>

          {/* Primary CTAs */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1 w-full sm:w-auto">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="w-full sm:w-auto min-h-[44px] px-5 py-2.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs sm:text-sm font-semibold transition-colors shadow-lg shadow-teal-500/10 cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Import Assessment Report (.json)</span>
            </button>
            {onExploreDemo && (
              <button
                type="button"
                onClick={onExploreDemo}
                className="w-full sm:w-auto min-h-[44px] px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-teal-500/40 text-teal-300 hover:text-teal-200 text-xs sm:text-sm font-semibold transition-colors cursor-pointer flex items-center justify-center gap-2"
              >
                <span>Explore Demo</span>
                <span className="text-[11px] font-normal text-slate-400">(No AWS needed)</span>
              </button>
            )}
          </div>
        </header>

        {/* Resume Current In-Memory Report */}
        {onResumeReport && (
          <div className="rounded-xl border border-teal-500/30 bg-teal-950/20 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs">
            <span className="text-teal-200">
              You have an imported report open in memory for{" "}
              <span className="font-mono font-semibold">Account {maskAccountId(resumableAccountId)}</span>.
            </span>
            <button
              type="button"
              onClick={onResumeReport}
              className="text-xs font-semibold text-teal-300 hover:text-teal-200 underline underline-offset-2 cursor-pointer bg-transparent border-none p-0 self-start sm:self-auto"
            >
              Return to Dashboard →
            </button>
          </div>
        )}

        {/* Local Report Dropzone */}
        <section
          id="import-report"
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`rounded-xl border-2 border-dashed p-5 sm:p-6 text-center transition-colors ${
            isDragging
              ? "border-teal-400 bg-teal-950/25"
              : "border-slate-700/80 bg-slate-900/50 hover:border-slate-600"
          }`}
        >
          <input
            ref={fileInputRef}
            id="report-file-input"
            type="file"
            accept=".json,application/json"
            onChange={handleFileInputChange}
            className="hidden"
          />
          <div className="space-y-2 max-w-md mx-auto">
            <p className="text-sm font-semibold text-white">
              Import Local Assessment JSON
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Drag and drop <code className="text-teal-300">aws-clarity-report.json</code> here, or select it from your
              computer. Processed 100% locally in browser memory—never uploaded to any server.
            </p>
            <div className="pt-1.5">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 text-xs font-semibold cursor-pointer transition-colors"
              >
                Choose Local JSON File
              </button>
            </div>
            <p className="text-[11px] text-slate-500">
              Max 25 MB · Strict schema &amp; credential-leak validation · Never executes imported content
            </p>
          </div>

          {importError && (
            <div className="mt-4 flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30 text-left break-words">
              <span className="text-red-400 font-bold shrink-0">⚠</span>
              <span className="min-w-0">{importError}</span>
            </div>
          )}
        </section>

        {/* 10 Supported AWS Services + Clear Default (9) vs Optional S3 (1) Breakdown */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 sm:p-5 space-y-3.5">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                AWS Clarity Supports 10 AWS Services · 17 Resource Types · 43 Rules (v1)
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                A normal default scan assesses <strong className="text-slate-200">9 services</strong>; S3 is excluded by default unless you explicitly opt in.
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

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-[11px]">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-emerald-300">Default Assessment: 9 Services</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                  Zero Request Charges
                </span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Uses 28 free AWS control-plane read APIs across:
              </p>
              <div className="flex flex-wrap gap-1">
                {SUPPORTED_SERVICES.filter((svc) => svc !== "S3").map((svc) => (
                  <span
                    key={svc}
                    className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-200"
                  >
                    {svc}
                  </span>
                ))}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-sky-500/30 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-sky-300">Optional S3 Assessment: 1 Service</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                  Requires Consent
                </span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                <strong className="text-slate-200">Excluded by default:</strong> S3 public policy (<code className="text-slate-300">S3-002</code>),
                public ACL (<code className="text-slate-300">S3-003</code>), encryption (<code className="text-slate-300">S3-004</code>), and Block Public Access (<code className="text-slate-300">S3-005</code>).
              </p>
              <p className="text-[10px] text-slate-400 leading-relaxed">
                <strong className="text-slate-300">Why optional:</strong> Outside an account&apos;s 12-month S3 Free Tier, AWS S3 bills <code className="text-slate-300">ListBuckets</code> ($0.005/1k LIST) and <code className="text-slate-300">GetBucket*</code> ($0.0004/1k GET). Opt in with <code className="text-sky-300">--include-s3-checks</code>; skipped S3 checks are marked <code className="text-sky-300">SKIPPED_OPTIONAL</code>, never Healthy.
              </p>
            </div>
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
                Intentionally out of scope in v1: Cost Explorer/Billing APIs (paid), GuardDuty/Config/Security Hub (paid), AWS services outside these 10, and customer data contents.
              </p>
            </div>
          )}
        </section>

        {/* Getting Started: Local Scanner Guide */}
        <section id="getting-started" className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-white">Getting Started — Run Locally in 3 Steps</h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Works on macOS, Linux, and Windows with Python 3.10+ and your existing AWS CLI / IAM Identity Center profile.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-xs text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0 shrink-0"
            >
              Security &amp; Privacy Boundaries →
            </button>
          </div>

          {/* STEP 1 — Review & Attach Read-Only IAM Policy (Customer-Owned) */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-100">
                  <span className="text-teal-400 mr-1.5">Step 1.</span>
                  Review Read-Only Permissions (28 Default Free / 34 With Optional S3)
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Attach to your own IAM Identity Center permission set or read-only IAM role. No vendor cross-account trust required.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowPermissionPreview((prev) => !prev)}
                className="text-xs font-medium text-teal-400 hover:text-teal-300 cursor-pointer bg-transparent border-none p-0 shrink-0"
              >
                {showPermissionPreview ? "Hide permission preview ▲" : "Preview all permissions & costs ▼"}
              </button>
            </div>

            {showPermissionPreview && (
              <div className="pt-2 border-t border-slate-800 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                    <div key={grp.service} className="p-2.5 rounded-lg bg-slate-900/70 border border-slate-800/80 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[11px] font-semibold text-slate-200">{grp.service}</p>
                        {grp.optional && (
                          <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                            Optional
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-teal-300/90">{grp.costNote}</p>
                      <p className="text-[10px] text-slate-400 leading-relaxed">{grp.summary}</p>
                      <p className="text-[10px] font-mono text-slate-500 break-all">
                        {grp.actions.join(", ")}
                      </p>
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
                          : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      28 Actions (Default Zero-Cost)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPolicyVariant("with-s3")}
                      className={`text-[11px] px-2.5 py-1 rounded border cursor-pointer ${
                        policyVariant === "with-s3"
                          ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                          : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      34 Actions (With Optional S3)
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setShowPolicyJson((prev) => !prev)}
                      className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
                    >
                      {showPolicyJson ? "Hide JSON ▲" : "View JSON ▼"}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy("policy", activePolicyJson)}
                      className="text-[11px] text-slate-300 hover:text-white font-medium cursor-pointer bg-slate-800/70 border border-slate-700 px-2.5 py-1 rounded"
                    >
                      {copiedKey === "policy" ? "Copied ✓" : "Copy Policy JSON"}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        downloadLocalFile(activePolicyFilename, `${activePolicyJson}\n`, "application/json;charset=utf-8;")
                      }
                      className="text-[11px] text-teal-300 hover:text-teal-200 font-medium cursor-pointer bg-teal-500/10 border border-teal-500/30 px-2.5 py-1 rounded"
                    >
                      Download JSON
                    </button>
                  </div>
                </div>

                {showPolicyJson && (
                  <pre className="text-[10px] text-slate-300 p-2.5 overflow-x-auto max-h-48 font-mono leading-relaxed bg-slate-950 rounded border border-slate-800">
                    {activePolicyJson}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* STEP 2 — Authenticate & Run Local Scanner */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-100">
                  <span className="text-teal-400 mr-1.5">Step 2.</span>
                  Install &amp; Run the Local Scanner Using Your AWS CLI Profile
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Verify your active AWS identity locally, check permissions, and generate your report JSON.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  handleCopy(
                    "cli-quickstart",
                    [
                      "# 1. Install locally from verified public source",
                      "git clone https://github.com/DavidDanso/aws-clarity.git && cd aws-clarity",
                      "python3 -m venv .venv && source .venv/bin/activate && pip install .",
                      "",
                      "# 2. Sign in with your AWS CLI / IAM Identity Center profile",
                      "aws sso login --profile my-profile",
                      "aws sts get-caller-identity --profile my-profile",
                      "",
                      "# 3. Verify permissions & run local read-only scan",
                      "aws-clarity doctor --profile my-profile",
                      "aws-clarity scan --profile my-profile --output aws-clarity-report.json",
                    ].join("\n")
                  )
                }
                className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0 shrink-0"
              >
                {copiedKey === "cli-quickstart" ? "Copied Commands ✓" : "Copy Commands"}
              </button>
            </div>

            <pre className="text-[11px] text-slate-200 p-3 overflow-x-auto font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800">
{`# 1. Authenticate with your existing AWS CLI / IAM Identity Center profile
aws sso login --profile my-profile
aws sts get-caller-identity --profile my-profile

# 2. Verify identity, enabled regions, and read-only permissions locally
aws-clarity doctor --profile my-profile

# 3. Generate local JSON report (9 zero-request-charge services by default)
aws-clarity scan --profile my-profile --output aws-clarity-report.json

# Optional: include S3 bucket configuration checks (prompts for cost consent)
aws-clarity scan --profile my-profile --include-s3-checks --output aws-clarity-report.json`}
            </pre>

            <p className="text-[11px] text-slate-500 leading-relaxed">
              Inspect source code and verify release SHA-256 checksums on{" "}
              <a
                href="https://github.com/DavidDanso/aws-clarity/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
              >
                GitHub Releases (DavidDanso/aws-clarity)
              </a>
              . Reports are written locally with <code className="text-slate-400">0600</code> permissions on macOS/Linux (standard user ACLs on Windows) and never contain AWS credentials.
            </p>
          </div>

          {/* STEP 3 — Import, Compare & Export Safely */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 space-y-2">
            <p className="text-xs font-semibold text-slate-100">
              <span className="text-teal-400 mr-1.5">Step 3.</span>
              Import Locally, Compare Fixes &amp; Share Sanitized Reports
            </p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Import <code className="text-teal-300">aws-clarity-report.json</code> above to explore findings, AWS API
              evidence, and manual remediation steps. After applying fixes in AWS and re-running the CLI, click{" "}
              <strong className="text-slate-200">Import Newer Report (Diff)</strong> in the dashboard to see{" "}
              <strong className="text-slate-200">New</strong>, <strong className="text-slate-200">Resolved</strong>, and{" "}
              <strong className="text-slate-200">Unchanged</strong> findings—or export a{" "}
              <strong className="text-slate-200">Sanitized Report</strong> with account IDs, ARNs, and IPs redacted for team review.
            </p>
          </div>
        </section>

        {/* Honest Security Boundary Callout */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 text-[11px] text-slate-400 leading-relaxed space-y-1">
          <p className="font-semibold text-slate-200">Honest Security Boundaries</p>
          <p>
            Local-first architecture eliminates central credential handling and central inventory storage, significantly
            reducing what an attacker could gain by compromising this static website. However, no software can guarantee
            zero breach risk: you should still inspect open-source updates, verify release checksums, and protect your
            workstation and local report files.
          </p>
        </section>

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
            <a
              href="https://github.com/DavidDanso/aws-clarity"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-teal-400 transition-colors font-medium"
            >
              Open Source on GitHub
            </a>
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
            Free · Privacy-first local execution · Strictly read-only · Zero backend data collection
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
