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

const WHEEL_URL =
  "https://github.com/DavidDanso/aws-clarity/releases/download/v1.0.0/aws_clarity-1.0.0-py3-none-any.whl";

const INSTALL_TABS = [
  {
    id: "pipx",
    label: "pipx (Easiest)",
    hint: "Recommended — installs `aws-clarity` cleanly in one command without touching your system Python.",
    installCmd: `pipx install ${WHEEL_URL}`,
    verifyCmd: "aws-clarity version",
    cliPrefix: "aws-clarity",
  },
  {
    id: "unix",
    label: "macOS / Linux",
    hint: "Uses Python 3.10+ built-in virtual environment (no pipx needed).",
    installCmd: `python3 -m venv ~/.aws-clarity && ~/.aws-clarity/bin/pip install ${WHEEL_URL}`,
    verifyCmd: "~/.aws-clarity/bin/aws-clarity version",
    cliPrefix: "~/.aws-clarity/bin/aws-clarity",
  },
  {
    id: "windows",
    label: "Windows (PowerShell)",
    hint: "Uses Python 3.10+ built-in virtual environment in PowerShell.",
    installCmd: `py -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install ${WHEEL_URL}`,
    verifyCmd: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe" version`,
    cliPrefix: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe"`,
  },
];

const FAQ_ITEMS = [
  {
    question: "Is this safe to run on my real AWS account?",
    answer:
      "Yes. AWS Clarity is strictly read-only—it only reads configuration metadata (like security group rules, MFA status, and unattached volumes) and never creates, edits, or deletes anything in AWS. It never reads S3 file contents, database rows, Lambda code, or secrets.",
  },
  {
    question: "Will running a scan add charges to my AWS bill?",
    answer:
      "By default, no. A normal scan checks 9 AWS services using free AWS control-plane read APIs. S3 is skipped by default because S3 charges small per-request fees outside your 12-month Free Tier—if you want S3 checked too, check the optional S3 box and confirm the prompt.",
  },
  {
    question: "Does this website upload, see, or save my AWS report?",
    answer:
      "Never. When you pick or drop your JSON file, your browser reads it in memory only. This static site enforces Content-Security-Policy connect-src 'none', which tells your browser to block outbound data requests completely. Close the tab and your report disappears from memory.",
  },
  {
    question: "What if I use AWS SSO, a read-only role, or have a large AWS account?",
    answer:
      "The scanner uses your normal AWS CLI setup: sign in with `aws sso login --profile your-profile` (or pass `--role-arn` for your own read-only role). Large accounts scan across all enabled regions with a 90-second default budget—if a region times out, Clarity honestly marks coverage Incomplete and lets you scan specific regions with `--regions us-east-1,eu-west-1`.",
  },
  {
    question: "How can I share findings with my team without leaking Account IDs or IPs?",
    answer:
      "Once your report is open in the dashboard, click 'Export / Share Report' and choose Sanitized JSON or Sanitized CSV. Clarity strips AWS Account IDs, ARNs, resource names, and IP addresses so you can share findings safely in Slack, Jira, or GitHub.",
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
  const tabRefs = useRef([]);

  const [installTab, setInstallTab] = useState("pipx");
  const [includeS3, setIncludeS3] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const [policyVariant, setPolicyVariant] = useState("default");
  const [showPolicyJson, setShowPolicyJson] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  const activeInstall = INSTALL_TABS.find((t) => t.id === installTab) || INSTALL_TABS[0];
  const s3Flag = includeS3 ? " --include-s3-checks" : "";
  const scanCommand = `${activeInstall.cliPrefix} scan${s3Flag} --output aws-clarity-report.json`;
  const doctorCommand = `${activeInstall.cliPrefix} doctor${s3Flag}`;

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

  const handleTabKeyDown = (e, idx) => {
    let nextIdx = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % INSTALL_TABS.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + INSTALL_TABS.length) % INSTALL_TABS.length;
    else if (e.key === "Home") nextIdx = 0;
    else if (e.key === "End") nextIdx = INSTALL_TABS.length - 1;

    if (nextIdx !== null) {
      e.preventDefault();
      setInstallTab(INSTALL_TABS[nextIdx].id);
      tabRefs.current[nextIdx]?.focus();
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
    <div className="min-h-[100dvh] bg-slate-950 flex flex-col items-center justify-start px-4 sm:px-6 lg:px-8 py-5 sm:py-8 pb-20 text-slate-100">
      <div className="w-full max-w-3xl flex flex-col space-y-8 sm:space-y-10">
        {/* Compact Single-Row Top Bar */}
        <header className="flex items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2 text-sm font-semibold text-white">
            <span className="w-7 h-7 rounded-lg bg-teal-500/15 border border-teal-500/30 flex items-center justify-center text-teal-400">
              <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
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
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/70 hover:border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
            <span>Trust &amp; Privacy</span>
          </button>
        </header>

        {/* Hero: 5-Second Plain-English Understanding */}
        <section className="text-center flex flex-col items-center space-y-4 pt-1 sm:pt-3">
          <p className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-medium">
            Free · Runs on your computer · Zero uploads
          </p>

          <h1 className="text-2xl sm:text-4xl font-bold text-white tracking-tight max-w-2xl leading-[1.15]">
            See what&apos;s risky or wasting money in your AWS account.
          </h1>

          <p className="text-sm sm:text-[15px] text-slate-400 max-w-xl leading-relaxed">
            Run one read-only command on your laptop, drop the report file below, and get clear,
            evidence-backed fixes right in your browser. Your AWS credentials and account data never
            leave your machine.
          </p>

          {/* Primary CTAs — Try Demo first for zero-friction curiosity, Import for returning users */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-1 w-full sm:w-auto">
            {onExploreDemo && (
              <button
                type="button"
                onClick={onExploreDemo}
                className="w-full sm:w-auto min-h-[46px] px-6 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm font-bold transition-colors shadow-lg shadow-teal-500/15 cursor-pointer flex items-center justify-center gap-2"
              >
                <span>Explore Live Demo</span>
                <span className="text-xs font-medium opacity-80">(No AWS needed)</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="w-full sm:w-auto min-h-[46px] px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-100 text-sm font-semibold transition-colors cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Import Report (.json)</span>
            </button>
          </div>

          {/* Calm single-row reassurance */}
          <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5 pt-1 text-xs text-slate-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="text-teal-400">✓</span> Strictly read-only
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="text-teal-400">✓</span> Works with AWS CLI &amp; SSO
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="text-teal-400">✓</span> $0 AWS API fees by default
            </span>
          </div>
        </section>

        {/* Resume Current In-Memory Report (only shown when returning from a loaded real report) */}
        {onResumeReport && (
          <div className="rounded-xl border border-teal-500/35 bg-teal-950/25 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs">
            <span className="text-teal-200">
              Your report for{" "}
              <strong className="font-mono">Account {maskAccountId(resumableAccountId)}</strong> is still open in browser memory.
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

        {/* Hidden file input shared by hero CTA and Step 3 dropzone */}
        <input
          ref={fileInputRef}
          id="report-file-input"
          type="file"
          accept=".json,application/json"
          onChange={handleFileInputChange}
          className="hidden"
        />

        {/* Guided 3-Step Onboarding Flow */}
        <section aria-labelledby="steps-heading" className="space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="steps-heading" className="text-base sm:text-lg font-bold text-white">
              Scan your own AWS account in 3 easy steps
            </h2>
            <span className="text-xs text-slate-400">Takes ~2 minutes · Python 3.10+</span>
          </div>

          {/* STEP 1 — Install */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4">
            <div className="flex items-start gap-3">
              <span className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5">
                1
              </span>
              <div className="space-y-1 min-w-0">
                <h3 className="text-sm sm:text-base font-semibold text-white">
                  Install the local scanner
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  <strong className="text-slate-300">Why:</strong> Running it on your own computer means this website never asks for your AWS keys or connects to your AWS account.
                </p>
              </div>
            </div>

            {/* Accessible single-row install method tabs */}
            <div className="space-y-3">
              <div
                role="tablist"
                aria-label="Choose how to install the scanner"
                className="flex items-center gap-1 border-b border-slate-800 overflow-x-auto no-scrollbar"
              >
                {INSTALL_TABS.map((tab, idx) => {
                  const selected = installTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      ref={(el) => {
                        tabRefs.current[idx] = el;
                      }}
                      type="button"
                      role="tab"
                      id={`install-tab-${tab.id}`}
                      aria-selected={selected}
                      tabIndex={selected ? 0 : -1}
                      onClick={() => setInstallTab(tab.id)}
                      onKeyDown={(e) => handleTabKeyDown(e, idx)}
                      className={`clarity-tab shrink-0 px-3 py-2 text-xs font-medium cursor-pointer bg-transparent border-0 transition-colors whitespace-nowrap ${
                        selected ? "text-teal-300" : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {tab.label}
                    </button>
                  );
                })}
              </div>

              {INSTALL_TABS.map((tab) => {
                const selected = installTab === tab.id;
                return (
                  <div
                    key={tab.id}
                    role="tabpanel"
                    aria-labelledby={`install-tab-${tab.id}`}
                    hidden={!selected}
                  >
                    <div className="space-y-2.5">
                      <p className="text-xs text-slate-400">{tab.hint}</p>
                      <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-3 pr-20">
                        <pre className="text-xs text-slate-100 font-mono overflow-x-auto leading-relaxed">
                          {tab.installCmd}
                        </pre>
                        <button
                          type="button"
                          onClick={() => handleCopy(`install-${tab.id}`, tab.installCmd)}
                          className="absolute top-2.5 right-2.5 text-[11px] font-medium px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
                        >
                          {copiedKey === `install-${tab.id}` ? "Copied ✓" : "Copy"}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5">
              <p className="text-emerald-200/90 leading-relaxed">
                <strong className="text-emerald-300">What to expect:</strong> Running{" "}
                <code className="text-emerald-200">{activeInstall.verifyCmd}</code> prints{" "}
                <code className="text-slate-200">aws-clarity 1.0.0 (local-first, read-only, zero telemetry)</code>.
              </p>
            </div>

            <p className="text-[11px] text-slate-500">
              Want to verify the package before installing? Inspect the open-source code and SHA-256 checksums on{" "}
              <a
                href="https://github.com/DavidDanso/aws-clarity/releases/tag/v1.0.0"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-400 hover:text-teal-300 underline underline-offset-2"
              >
                GitHub Releases (v1.0.0)
              </a>
              .
            </p>
          </div>

          {/* STEP 2 — Run Scan */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4">
            <div className="flex items-start gap-3">
              <span className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5">
                2
              </span>
              <div className="space-y-1 min-w-0">
                <h3 className="text-sm sm:text-base font-semibold text-white">
                  Run a read-only scan
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  <strong className="text-slate-300">Why:</strong> Uses your existing AWS CLI or SSO login to inspect 9 core services with free read APIs and saves a private report file on your machine.
                </p>
              </div>
            </div>

            {/* Visible Recommended Read-Only Role Callout (Phase 1.7 — outside any collapsed section) */}
            <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-3.5 py-3 text-xs space-y-1.5">
              <p className="font-semibold text-amber-200">
                Recommended: use a dedicated read-only role first
              </p>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Avoid running any local scanner with AWS account root or broad admin credentials.
                (Root credentials are refused by default; using a dedicated read-only role is recommended
                to limit blast radius.)
              </p>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 pt-0.5 text-[11px]">
                <a
                  href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/IAM_PERMISSIONS.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-2"
                >
                  View least-privilege IAM policy (28/34 actions)
                </a>
                <span className="text-slate-600">·</span>
                <button
                  type="button"
                  onClick={() =>
                    downloadLocalFile(
                      "aws-clarity-readonly-policy-default.json",
                      `${IAM_POLICY_DEFAULT_JSON}\n`,
                      "application/json;charset=utf-8;"
                    )
                  }
                  className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer"
                >
                  Download policy JSON
                </button>
                <span className="text-slate-600">·</span>
                <a
                  href="https://github.com/DavidDanso/aws-clarity/blob/main/infra/aws-clarity-readonly-role.yaml"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-2"
                >
                  CloudFormation read-only role template
                </a>
              </div>
            </div>

            <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-3 pr-20">
              <pre className="text-xs text-slate-100 font-mono overflow-x-auto leading-relaxed">
                <span>{activeInstall.cliPrefix} scan</span>
                {includeS3 && (
                  <span className="mx-1 px-1.5 py-0.5 rounded bg-sky-500/20 border border-sky-400/40 text-sky-200 font-semibold">
                    --include-s3-checks
                  </span>
                )}
                <span> --output aws-clarity-report.json</span>
              </pre>
              <button
                type="button"
                onClick={() => handleCopy("scan-cmd", scanCommand)}
                className="absolute top-2.5 right-2.5 text-[11px] font-medium px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
              >
                {copiedKey === "scan-cmd" ? "Copied ✓" : "Copy"}
              </button>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 text-xs">
              <label className="inline-flex items-start gap-2 cursor-pointer text-slate-300 select-none">
                <input
                  type="checkbox"
                  checked={includeS3}
                  onChange={(e) => setIncludeS3(e.target.checked)}
                  className="mt-0.5 rounded border-slate-700 bg-slate-950 text-teal-500 focus:ring-teal-500 cursor-pointer"
                />
                <span>
                  Also check S3 buckets <span className="text-slate-500">(optional — asks for cost consent; small S3 API fees may apply outside Free Tier)</span>
                </span>
              </label>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed">
              Using a named AWS profile or SSO? Add <code className="text-teal-300">--profile your-profile</code> (after <code className="text-slate-300">aws sso login</code>). Want to test your login &amp; permissions first? Run{" "}
              <code className="text-slate-200">{doctorCommand}</code>.
            </p>

            <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs text-emerald-200/90 leading-relaxed">
              <strong className="text-emerald-300">What to expect:</strong> After ~30–60 seconds, your terminal prints{" "}
              <code className="text-slate-200">Scan complete — Saved local report: aws-clarity-report.json</code>{" "}
              with your summary counts. Nothing in AWS is ever modified.
            </div>
          </div>

          {/* STEP 3 — Drop Report Here */}
          <div
            id="import-report"
            className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4"
          >
            <div className="flex items-start gap-3">
              <span className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5">
                3
              </span>
              <div className="space-y-1 min-w-0">
                <h3 className="text-sm sm:text-base font-semibold text-white">
                  Drop your report here to explore it
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  <strong className="text-slate-300">Why:</strong> Parsed 100% inside your browser tab (<code className="text-slate-300">connect-src &apos;none&apos;</code> blocks network uploads). Close the tab and it&apos;s gone.
                </p>
              </div>
            </div>

            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              className={`rounded-xl border-2 border-dashed p-6 sm:p-8 text-center transition-colors ${
                isDragging
                  ? "border-teal-400 bg-teal-950/30"
                  : "border-slate-700 bg-slate-950/70 hover:border-teal-500/50"
              }`}
            >
              <div className="space-y-3 max-w-sm mx-auto">
                <p className="text-sm font-semibold text-white">
                  Drag &amp; drop <code className="text-teal-300">aws-clarity-report.json</code> here
                </p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-5 py-2.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs sm:text-sm font-semibold cursor-pointer transition-colors"
                >
                  Choose Local Report File
                </button>
                <p className="text-[11px] text-slate-500">
                  Max 25 MB · Rejects AWS credential files automatically · Zero server upload
                </p>
              </div>

              {importError && (
                <div className="mt-4 flex items-start gap-2 border border-red-800/50 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/40 text-left break-words">
                  <span className="text-red-400 font-bold shrink-0">⚠</span>
                  <span className="min-w-0">{importError}</span>
                </div>
              )}
            </div>

            <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs text-emerald-200/90 leading-relaxed">
              <strong className="text-emerald-300">What to expect:</strong> Your interactive dashboard opens immediately with prioritized risks, exact AWS proof, step-by-step manual fixes, Scan Diff (to verify fixes later), and safe redacted sharing.
            </div>
          </div>
        </section>

        {/* Secondary Technical Reference — Collapsed on Demand (Zero Visual Clutter) */}
        <section aria-labelledby="details-heading" className="space-y-3">
          <h2 id="details-heading" className="sr-only">
            Technical details and permissions
          </h2>

          <details className="clarity-disclosure rounded-2xl border border-slate-800 bg-slate-900/40 px-4 sm:px-5 py-3.5">
            <summary className="text-xs sm:text-sm font-semibold text-slate-200 hover:text-white transition-colors">
              <span>What AWS services &amp; IAM permissions does it use? (9 free + optional S3)</span>
            </summary>

            <div className="pt-4 mt-3 border-t border-slate-800/80 space-y-5 text-xs">
              {/* 9 Default vs Optional S3 */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-emerald-300">Default: 9 Services</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                      28 Free Read APIs
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {SUPPORTED_SERVICES.filter((svc) => svc !== "S3").map((svc) => (
                      <span
                        key={svc}
                        className="text-[11px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-200"
                      >
                        {svc}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-sky-500/30 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-sky-300">Optional: S3 Buckets</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                      +6 Actions (Opt-in)
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Checks public bucket policies, ACLs, and Block Public Access without listing or reading your files. Skipped S3 checks are marked <code className="text-sky-300">SKIPPED_OPTIONAL</code>, never Healthy.
                  </p>
                </div>
              </div>

              {/* Compact 10-Service Coverage Table */}
              <div className="rounded-xl border border-slate-800 bg-slate-950 divide-y divide-slate-800/70 overflow-hidden text-[11px]">
                {SERVICE_COVERAGE_MATRIX.map((row) => (
                  <div key={row.service} className="p-2.5 grid grid-cols-1 sm:grid-cols-12 gap-1 sm:gap-3">
                    <div className="sm:col-span-3">
                      <span className="font-semibold text-teal-300">{row.service}</span>
                      <span className="block text-[10px] text-slate-500">{row.scope}</span>
                    </div>
                    <div className="sm:col-span-4 text-slate-300">{row.resources.join(", ")}</div>
                    <div className="sm:col-span-5 text-slate-400 leading-relaxed">{row.checks}</div>
                  </div>
                ))}
              </div>

              {/* Least-Privilege IAM Policy Preview & Download */}
              <div className="space-y-2.5">
                <p className="font-semibold text-slate-200">
                  Need a least-privilege IAM policy for your team or AWS SSO permission set?
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                    <div key={grp.service} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-semibold text-slate-200">{grp.service}</span>
                        <span className="text-[10px] font-mono text-slate-500">{grp.actions.length} actions</span>
                      </div>
                      <p className="text-[10px] text-slate-400 leading-relaxed">{grp.summary}</p>
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
                          : "bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200"
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
                          : "bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      34 Actions (With S3)
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setShowPolicyJson((prev) => !prev)}
                      className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
                    >
                      {showPolicyJson ? "Hide JSON" : "View JSON"}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy("policy", activePolicyJson)}
                      className="text-[11px] text-slate-300 hover:text-white font-medium cursor-pointer bg-slate-800 border border-slate-700 px-2.5 py-1 rounded"
                    >
                      {copiedKey === "policy" ? "Copied ✓" : "Copy Policy"}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        downloadLocalFile(
                          activePolicyFilename,
                          `${activePolicyJson}\n`,
                          "application/json;charset=utf-8;"
                        )
                      }
                      className="text-[11px] text-teal-300 hover:text-teal-200 font-medium cursor-pointer bg-teal-500/10 border border-teal-500/30 px-2.5 py-1 rounded"
                    >
                      Download JSON
                    </button>
                  </div>
                </div>

                {showPolicyJson && (
                  <pre className="text-[10px] text-slate-300 p-3 overflow-x-auto max-h-48 font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800">
                    {activePolicyJson}
                  </pre>
                )}
              </div>
            </div>
          </details>
        </section>

        {/* Plain-Language FAQ — Native Non-Exclusive <details> Accordion */}
        <section aria-labelledby="faq-heading" className="space-y-2.5">
          <h2 id="faq-heading" className="text-sm font-bold text-slate-200">
            Common Questions
          </h2>
          <div className="rounded-2xl border border-slate-800/90 bg-slate-900/35 divide-y divide-slate-800/80 overflow-hidden">
            {FAQ_ITEMS.map((item) => (
              <details key={item.question} className="clarity-disclosure px-4 sm:px-5 py-3.5">
                <summary className="text-xs sm:text-[13px] font-medium text-slate-200 hover:text-white transition-colors">
                  <span>{item.question}</span>
                </summary>
                <p className="text-xs text-slate-400 pt-2.5 pl-4 leading-relaxed">
                  {item.answer}
                </p>
              </details>
            ))}
          </div>
        </section>

        {/* Minimal Footer */}
        <footer className="pt-4 border-t border-slate-800/70 flex flex-col items-center gap-2 text-xs text-slate-500">
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
              Open Source (MIT)
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
            Local-only execution · Strictly read-only · Zero backend data collection
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
