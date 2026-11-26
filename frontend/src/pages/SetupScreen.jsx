import { useRef, useState } from "react";
import { maskAccountId } from "../utils/formatters";
import {
  IAM_POLICY_DEFAULT_JSON,
  IAM_POLICY_JSON,
  PERMISSION_PREVIEW_GROUPS,
  SERVICE_COVERAGE_MATRIX,
  SUPPORTED_SERVICES,
} from "../utils/constants";
import {
  MAX_REPORT_BYTES,
  parseLocalAssessmentReport,
  sanitizeImportedFileName,
} from "../utils/reportImporter";
import { downloadLocalFile } from "../utils/reportSanitizer";
import TrustModal from "../components/TrustModal";

const PROPOSED_VERSION = "1.1.0";
const PROPOSED_WHEEL_FILE = `aws_clarity-${PROPOSED_VERSION}-py3-none-any.whl`;
const REPO_CLONE_URL = "https://github.com/DavidDanso/aws-clarity.git";

const INSTALL_TABS = [
  {
    id: "pipx",
    label: "pipx (Recommended)",
    hint: "Installs `aws-clarity` in an isolated CLI environment without modifying system Python (requires Python 3.10+ and pipx).",
    installCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npipx install .`,
    releaseWheelCmd: `pipx install ./${PROPOSED_WHEEL_FILE}`,
    verifyCmd: "aws-clarity version",
    cliPrefix: "aws-clarity",
  },
  {
    id: "unix",
    label: "macOS / Linux (venv)",
    hint: "Uses Python 3.10+ built-in virtual environment — no pipx required.",
    installCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npython3 -m venv ~/.aws-clarity\n~/.aws-clarity/bin/pip install .`,
    releaseWheelCmd: `python3 -m venv ~/.aws-clarity && ~/.aws-clarity/bin/pip install ./${PROPOSED_WHEEL_FILE}`,
    verifyCmd: "~/.aws-clarity/bin/aws-clarity version",
    cliPrefix: "~/.aws-clarity/bin/aws-clarity",
  },
  {
    id: "windows",
    label: "Windows (PowerShell)",
    hint: "Uses Python 3.10+ built-in virtual environment in PowerShell.",
    installCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npy -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .`,
    releaseWheelCmd: `py -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .\\${PROPOSED_WHEEL_FILE}`,
    verifyCmd: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe" version`,
    cliPrefix: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe"`,
  },
];

const VERIFY_CHECKSUM_COMMANDS = [
  {
    id: "checksum-macos",
    os: "macOS",
    cmd: "shasum -a 256 -c SHA256SUMS.txt",
    note: "Run in the folder containing the downloaded release file and SHA256SUMS.txt. Look for `: OK`.",
  },
  {
    id: "checksum-linux",
    os: "Linux",
    cmd: "sha256sum -c SHA256SUMS.txt",
    note: "Run in the folder containing the downloaded release file and SHA256SUMS.txt. Look for `: OK`.",
  },
  {
    id: "checksum-windows",
    os: "Windows (PowerShell)",
    cmd: `(Get-FileHash .\\${PROPOSED_WHEEL_FILE} -Algorithm SHA256).Hash.ToLower()`,
    note: `Compare the 64-character hex hash printed by PowerShell against the ${PROPOSED_WHEEL_FILE} line in SHA256SUMS.txt.`,
  },
];

const FAQ_ITEMS = [
  {
    question: "Can I use AWS Clarity with a production AWS account?",
    answer:
      "AWS Clarity is a local Python CLI that runs under the AWS credentials you choose. It is designed to call only allowlisted read-only AWS APIs and does not intentionally modify AWS resources, and its local-first architecture avoids sending reports to an AWS Clarity backend. However, read-only configuration metadata can still be sensitive, the supported v1 rules do not cover every AWS service or security issue, and the health score is not a security certification. Use a dedicated read-only IAM role or IAM Identity Center permission set, and review the open-source code and IAM policy before running unfamiliar software against production—you remain responsible for reviewing and authorizing tools run with your credentials.",
  },
  {
    question: "Will running a scan add charges to my AWS bill?",
    answer:
      "By default, no. A standard scan inspects 9 AWS services using 28 free AWS control-plane read APIs. S3 is skipped by default (`SKIPPED_OPTIONAL`) because S3 LIST and GET requests can incur small AWS charges outside an account's 12-month S3 Free Tier. If you opt in with `--include-s3-checks`, the CLI displays S3 pricing and asks for explicit consent before calling any S3 API.",
  },
  {
    question: "Does this website upload, see, or save my AWS report?",
    answer:
      "No. You can turn off your Wi-Fi after loading this page and import your report completely offline. Reports are parsed strictly in browser memory and are not automatically saved to localStorage or sessionStorage. Production builds enforce Content-Security-Policy `connect-src 'none'`, blocking outbound data requests from the app. Closing or refreshing the tab removes the active report state.",
  },
  {
    question: "What if I use AWS SSO, a read-only role, or have a large AWS account?",
    answer:
      "AWS Clarity uses your existing AWS CLI setup: sign in with `aws sso login --profile your-profile`, pass `--profile your-profile` (or `--role-arn` to assume your own read-only role locally), and run `aws-clarity doctor` to probe read permissions first. Large accounts scan across all enabled regions with a 90-second default time budget—if any region times out or lacks permissions, coverage is marked INCOMPLETE and you can scope runs with `--regions us-east-1,eu-west-1`.",
  },
  {
    question: "How can I share findings without exposing Account IDs or IPs?",
    answer:
      "In the dashboard, open Export and choose Download Sanitized JSON or Download Sanitized CSV. Sanitized exports use best-effort redaction to strip Account IDs, ARNs, access key IDs, resource names, and IPs—they are not guaranteed to be completely anonymous, so always inspect the exported file before sharing. Full exports contain sensitive infrastructure identifiers and should stay private.",
  },
  {
    question: "What if Python, pipx, or AWS credentials are missing or failing?",
    answer:
      "If `python3` or `py` is missing, install Python 3.10+ from python.org first. If `pipx` is unavailable, switch to the macOS / Linux (venv) or Windows (PowerShell) tab in Step 1. If AWS SSO has expired, run `aws sso login --profile your-profile` and confirm with `aws sts get-caller-identity`. See docs/TROUBLESHOOTING.md for step-by-step recovery.",
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
  const mainRef = useRef(null);
  const tabRefs = useRef([]);

  const [installTab, setInstallTab] = useState("pipx");
  const [includeS3, setIncludeS3] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const [statusAnnouncement, setStatusAnnouncement] = useState("");
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

  const handleCopy = async (key, text, label = "Command") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setStatusAnnouncement(`${label} copied to clipboard.`);
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
      if (typeof file.size === "number" && file.size > MAX_REPORT_BYTES) {
        throw new Error(
          "Report file exceeds the 25 MB local browser safety limit. " +
            "Why: Large files can freeze browser memory. " +
            "Next: Re-run `aws-clarity scan` with specific regions (e.g. `--regions us-east-1,eu-west-1`) and `--compact`."
        );
      }
      const text = await file.text();
      const parsed = parseLocalAssessmentReport(text, file.size);
      onImportReport(parsed, sanitizeImportedFileName(file.name));
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
    <div className="min-h-[100dvh] bg-slate-950 flex flex-col items-center justify-start px-4 sm:px-6 lg:px-8 py-5 sm:py-8 pb-24 text-slate-100">
      <button
        type="button"
        onClick={() => mainRef.current?.focus()}
        className="skip-link"
      >
        Skip to main content
      </button>

      {/* Polite screen-reader announcer for clipboard/copy confirmation */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {statusAnnouncement}
      </div>

      <div className="w-full max-w-3xl flex flex-col space-y-8 sm:space-y-10">
        {/* Compact Single-Row Top Bar */}
        <header className="flex items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2 text-sm font-semibold text-white min-w-0">
            <span
              aria-hidden="true"
              className="w-7 h-7 rounded-lg bg-teal-500/15 border border-teal-500/30 flex items-center justify-center text-teal-400 shrink-0"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            <span className="truncate">AWS Clarity</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-500/10 border border-teal-500/25 text-teal-300 shrink-0">
              Local-First
            </span>
          </div>
          <button
            type="button"
            onClick={() => setTrustModalOpen(true)}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/70 hover:border-slate-700 text-slate-200 hover:text-white transition-colors cursor-pointer flex items-center gap-1.5 shrink-0"
          >
            <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-teal-400" />
            <span>Trust &amp; Privacy</span>
          </button>
        </header>

        <main ref={mainRef} id="main-content" tabIndex={-1} className="space-y-8 sm:space-y-10 focus:outline-none">
          {/* Hero: 5-Second Plain-English Understanding */}
          <section className="text-center flex flex-col items-center space-y-4 pt-1 sm:pt-3">
            <p className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-medium">
              Free · Local-only CLI · Read-only · Zero uploads
            </p>

            <h1 className="text-2xl sm:text-4xl font-bold text-white tracking-tight max-w-2xl leading-[1.15]">
              Inspect your AWS configuration locally and see what to investigate first.
            </h1>

            <p className="text-sm sm:text-[15px] text-slate-300 max-w-xl leading-relaxed">
              AWS Clarity is an open-source, read-only assessment tool. Run the Python CLI on your own
              computer to check supported AWS infrastructure settings, then open the local JSON report in
              your browser—with clear evidence and manual remediation steps.
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

            {/* 5-Second At-a-Glance Grid: Answers all 9 core visitor questions calmly */}
            <div className="w-full pt-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-left">
              <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-3.5 space-y-1.5">
                <p className="text-xs font-semibold text-teal-300">What it inspects</p>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <strong>9 default AWS services</strong> (EC2, VPC, IAM, Lambda, RDS, DynamoDB, EBS,
                  CloudWatch, CloudTrail) plus <strong>optional S3</strong> bucket config—17 resource types
                  and 43 deterministic rules.
                </p>
              </div>
              <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-3.5 space-y-1.5">
                <p className="text-xs font-semibold text-teal-300">Where it runs &amp; privacy</p>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Scanner runs on <strong>your computer</strong> using strictly read-only AWS APIs. Never
                  modifies resources, never uploads reports, and never reads S3 files, DB rows, Lambda code,
                  or secrets.
                </p>
              </div>
              <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-3.5 space-y-1.5">
                <p className="text-xs font-semibold text-teal-300">AWS cost &amp; scope limits</p>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <strong>$0 AWS API fees</strong> by default (optional S3 may incur small AWS request fees
                  outside Free Tier). Does <strong>not</strong> assess other services (e.g. EKS, ECS, KMS,
                  Route 53) or estimate AWS bills.
                </p>
              </div>
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
                How to scan your AWS account in 3 steps
              </h2>
              <span className="text-xs text-slate-400">Takes ~2 minutes · Python 3.10+</span>
            </div>

            {/* STEP 1 — Install */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4">
              <div className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5"
                >
                  1
                </span>
                <div className="space-y-1 min-w-0">
                  <h3 className="text-sm sm:text-base font-semibold text-white">
                    Install the local scanner
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    <strong className="text-white">What you&apos;re doing:</strong> Installing the open-source{" "}
                    <code className="text-teal-300">aws-clarity</code> CLI locally so this website never asks
                    for AWS keys or connects to your AWS account.
                  </p>
                </div>
              </div>

              {/* Honest Release-Pending Notice for Hardened v1.1.0 */}
              <div className="rounded-xl border border-amber-500/35 bg-amber-950/25 px-3.5 py-3 text-xs space-y-1.5">
                <p className="font-semibold text-amber-200">
                  Release status: hardened v{PROPOSED_VERSION} package not yet published
                </p>
                <p className="text-[11px] text-slate-200 leading-relaxed">
                  The proposed hardened release artifacts (<code className="text-amber-200">{PROPOSED_WHEEL_FILE}</code>,{" "}
                  <code className="text-slate-200">aws_clarity-{PROPOSED_VERSION}.tar.gz</code>,{" "}
                  <code className="text-slate-200">aws-clarity-local-{PROPOSED_VERSION}.tar.gz</code>, and{" "}
                  <code className="text-slate-200">SHA256SUMS.txt</code>) have been tested locally and are{" "}
                  <strong>not yet published</strong> on GitHub Releases. The older published{" "}
                  <code className="text-slate-300">v1.0.0</code> release predates the read-only API allowlist,
                  root-account block, and pre-scan confirmation—install from the source checkout below or wait
                  for <code className="text-amber-200">v{PROPOSED_VERSION}</code> on{" "}
                  <a
                    href="https://github.com/DavidDanso/aws-clarity/releases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-teal-300 hover:text-teal-200 underline underline-offset-2"
                  >
                    GitHub Releases
                  </a>
                  .
                </p>
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
                        aria-controls={`install-panel-${tab.id}`}
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
                      id={`install-panel-${tab.id}`}
                      role="tabpanel"
                      aria-labelledby={`install-tab-${tab.id}`}
                      hidden={!selected}
                    >
                      <div className="space-y-2.5">
                        <p className="text-xs text-slate-300">{tab.hint}</p>
                        <div className="space-y-1.5">
                          <p className="text-[11px] font-medium text-slate-400">
                            Install from source checkout (available now):
                          </p>
                          <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-3 pr-20">
                            <pre className="text-xs text-slate-100 font-mono overflow-x-auto leading-relaxed">
                              {tab.installCmd}
                            </pre>
                            <button
                              type="button"
                              onClick={() => handleCopy(`install-${tab.id}`, tab.installCmd, `${tab.label} install command`)}
                              className="absolute top-2.5 right-2.5 text-[11px] font-medium px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
                            >
                              {copiedKey === `install-${tab.id}` ? "Copied ✓" : "Copy"}
                            </button>
                          </div>
                        </div>
                        <div className="space-y-1.5">
                          <p className="text-[11px] font-medium text-slate-400">
                            After v{PROPOSED_VERSION} is published &amp; verified locally (not yet published):
                          </p>
                          <div className="relative rounded-xl bg-slate-950/70 border border-slate-800/80 p-3 pr-20">
                            <pre className="text-xs text-slate-300 font-mono overflow-x-auto leading-relaxed">
                              {tab.releaseWheelCmd}
                            </pre>
                            <button
                              type="button"
                              onClick={() => handleCopy(`wheel-${tab.id}`, tab.releaseWheelCmd, `${tab.label} wheel install command`)}
                              className="absolute top-2.5 right-2.5 text-[11px] font-medium px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
                            >
                              {copiedKey === `wheel-${tab.id}` ? "Copied ✓" : "Copy"}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Visible Verify Before Installing Section */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 sm:p-4 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs font-semibold text-white">Verify Before Installing</p>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    SHA-256 Checksum Check
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  Once <code className="text-teal-300">v{PROPOSED_VERSION}</code> is published, download{" "}
                  <code className="text-slate-200">{PROPOSED_WHEEL_FILE}</code> and{" "}
                  <code className="text-slate-200">SHA256SUMS.txt</code> from GitHub Releases and check the
                  hash before installing. Note: a SHA-256 checksum confirms download integrity against the
                  manifest—it is <strong>not</strong> a digital signature (once published, you can also run{" "}
                  <code className="text-slate-200">gh attestation verify</code> to check GitHub Actions build
                  provenance).
                </p>
                <div className="space-y-2">
                  {VERIFY_CHECKSUM_COMMANDS.map((item) => (
                    <div
                      key={item.id}
                      className="rounded-lg bg-slate-900/80 border border-slate-800/90 p-2.5 space-y-1"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-semibold text-teal-300">{item.os}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(item.id, item.cmd, `${item.os} checksum command`)}
                          className="text-[10px] font-medium px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
                        >
                          {copiedKey === item.id ? "Copied ✓" : "Copy"}
                        </button>
                      </div>
                      <pre className="text-[11px] text-slate-100 font-mono overflow-x-auto leading-relaxed">
                        {item.cmd}
                      </pre>
                      <p className="text-[11px] text-slate-400">{item.note}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs">
                <p className="text-emerald-200/90 leading-relaxed">
                  <strong className="text-emerald-300">What happens next:</strong> Running{" "}
                  <code className="text-emerald-200">{activeInstall.verifyCmd}</code> prints{" "}
                  <code className="text-slate-200">aws-clarity {PROPOSED_VERSION} (local-first, read-only, zero telemetry)</code>.
                </p>
              </div>
            </div>

            {/* STEP 2 — Verify Identity & Run Scan */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4">
              <div className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5"
                >
                  2
                </span>
                <div className="space-y-1 min-w-0">
                  <h3 className="text-sm sm:text-base font-semibold text-white">
                    Verify AWS identity &amp; Run a read-only scan
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    <strong className="text-white">What you&apos;re doing:</strong> Authenticating via your
                    local AWS CLI or AWS SSO profile, confirming scope at the pre-scan prompt, and writing a
                    private JSON report file on your computer.
                  </p>
                </div>
              </div>

              {/* Visible Recommended Read-Only Role Callout (Phase 1.7 — outside any collapsed section) */}
              <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-3.5 py-3 text-xs space-y-2">
                <p className="font-semibold text-amber-200">
                  Recommended: use a dedicated read-only role first
                </p>
                <p className="text-[11px] text-slate-200 leading-relaxed">
                  Avoid running any local scanner with AWS account root or <code className="text-amber-200">AdministratorAccess</code>{" "}
                  credentials—root credentials are refused by default to protect your account. Using a
                  dedicated read-only role limits blast radius if anything on your workstation is compromised.
                  Note: a role is <strong>not</strong> safe simply because its name contains{" "}
                  <code className="text-slate-200">ReadOnly</code>, and AWS Clarity cannot prove your identity&apos;s
                  complete effective IAM permissions (SCPs, permission boundaries, and attached policies decide
                  real access).
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
                  <span aria-hidden="true" className="text-slate-600">·</span>
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
                  <span aria-hidden="true" className="text-slate-600">·</span>
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
                  onClick={() => handleCopy("scan-cmd", scanCommand, "Scan command")}
                  className="absolute top-2.5 right-2.5 text-[11px] font-medium px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 cursor-pointer transition-colors"
                >
                  {copiedKey === "scan-cmd" ? "Copied ✓" : "Copy"}
                </button>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 text-xs">
                <label className="inline-flex items-start gap-2 cursor-pointer text-slate-200 select-none">
                  <input
                    id="include-s3-checkbox"
                    type="checkbox"
                    checked={includeS3}
                    onChange={(e) => setIncludeS3(e.target.checked)}
                    className="mt-1 rounded border-slate-700 bg-slate-950 text-teal-500 focus:ring-teal-500 cursor-pointer shrink-0"
                  />
                  <span>
                    Also check S3 buckets{" "}
                    <span className="text-slate-400">
                      (optional — highlights <code className="text-sky-300">--include-s3-checks</code>, asks
                      for consent, and may incur small AWS S3 LIST/GET request charges outside Free Tier)
                    </span>
                  </span>
                </label>
              </div>

              {/* Plain-language Pre-Scan Details Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-[11px]">
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3 space-y-1 text-slate-300">
                  <p className="font-semibold text-slate-200">AWS SSO, regions &amp; pre-scan confirmation</p>
                  <p className="leading-relaxed text-slate-400">
                    Sign in with <code className="text-slate-200">aws sso login --profile your-profile</code> and
                    pass <code className="text-teal-300">--profile your-profile</code> (or check permissions first
                    with <code className="text-slate-200">{doctorCommand}</code>). Before collecting anything, the
                    CLI shows your masked account ID, target regions (all enabled regions by default), service
                    scope ({includeS3 ? "10 services with S3" : "9 default services; S3 off"}), and AWS fee status
                    so you can confirm or cancel.
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3 space-y-1 text-slate-300">
                  <p className="font-semibold text-slate-200">Collected vs deliberately not collected</p>
                  <p className="leading-relaxed text-slate-400">
                    <strong className="text-slate-200">Collected:</strong> allowlisted configuration metadata
                    only (security group rules, IAM MFA/key age, encryption flags, log retention, trails).{" "}
                    <strong className="text-slate-200">Never collected:</strong> S3 object lists/contents, DB rows,
                    Lambda code or env var values, tag values, descriptions, log events, or credentials.
                  </p>
                </div>
              </div>

              <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs text-emerald-200/90 leading-relaxed">
                <strong className="text-emerald-300">What happens next:</strong> After you confirm the pre-scan
                prompt, your terminal prints step-by-step progress by service and a final summary with the local
                path to <code className="text-slate-200">aws-clarity-report.json</code> (saved with owner-only
                permissions on macOS/Linux). Nothing in AWS is modified.
              </div>
            </div>

            {/* STEP 3 — Drop Report Here */}
            <div
              id="import-report"
              className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6 space-y-4"
            >
              <div className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className="w-7 h-7 rounded-full bg-teal-500/15 border border-teal-500/40 text-teal-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5"
                >
                  3
                </span>
                <div className="space-y-1 min-w-0">
                  <h3 className="text-sm sm:text-base font-semibold text-white">
                    Import your report locally
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    <strong className="text-white">Offline guarantee:</strong> You can turn off your Wi-Fi
                    before dropping your report file. It works the same.
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
                  <p className="text-[11px] text-slate-400">
                    Max 25 MB · Rejects AWS credential files automatically · Zero server upload
                  </p>
                </div>

                {importError && (
                  <div
                    role="alert"
                    className="mt-4 flex items-start gap-2 border border-red-800/60 rounded-lg px-3 py-2.5 text-xs text-red-200 bg-red-950/45 text-left break-words leading-relaxed"
                  >
                    <span aria-hidden="true" className="text-red-400 font-bold shrink-0">⚠</span>
                    <span className="min-w-0">{importError}</span>
                  </div>
                )}
              </div>

              <ul className="text-[11px] text-slate-300 space-y-1 list-disc pl-5 leading-relaxed">
                <li>
                  Imported strictly into <strong>browser memory</strong>—this website never uploads your report
                  and never automatically saves it to browser storage (<code className="text-slate-200">connect-src &apos;none&apos;</code>).
                </li>
                <li>
                  Closing or refreshing this tab clears the active application state immediately.
                </li>
                <li>
                  Full exports contain sensitive infrastructure identifiers (Account IDs, ARNs, IPs, names).
                  Sanitized exports use best-effort redaction and are <strong>not</strong> guaranteed completely
                  anonymous—always review before sharing.
                </li>
              </ul>

              <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/20 px-3.5 py-2.5 text-xs text-emerald-200/90 leading-relaxed">
                <strong className="text-emerald-300">What happens next:</strong> Your dashboard opens
                immediately with account overview, prioritized findings with AWS evidence and impact notes,
                local Scan Diff to verify fixes later, and redacted export options.
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
                <span>What AWS services &amp; IAM permissions does it use? (9 default + optional S3)</span>
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
                    <p className="text-[11px] text-slate-300 leading-relaxed">
                      Checks public bucket policies, ACLs, and Block Public Access without listing or reading
                      your files. Skipped S3 checks are marked <code className="text-sky-300">SKIPPED_OPTIONAL</code>,
                      never Healthy.
                    </p>
                  </div>
                </div>

                {/* Compact 10-Service Coverage Table */}
                <div className="rounded-xl border border-slate-800 bg-slate-950 divide-y divide-slate-800/70 overflow-hidden text-[11px]">
                  {SERVICE_COVERAGE_MATRIX.map((row) => (
                    <div key={row.service} className="p-2.5 grid grid-cols-1 sm:grid-cols-12 gap-1 sm:gap-3">
                      <div className="sm:col-span-3">
                        <span className="font-semibold text-teal-300">{row.service}</span>
                        <span className="block text-[10px] text-slate-400">{row.scope}</span>
                      </div>
                      <div className="sm:col-span-4 text-slate-200">{row.resources.join(", ")}</div>
                      <div className="sm:col-span-5 text-slate-300 leading-relaxed">{row.checks}</div>
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
                          <span className="text-[10px] font-mono text-slate-400">{grp.actions.length} actions</span>
                        </div>
                        <p className="text-[10px] text-slate-300 leading-relaxed">{grp.summary}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        aria-pressed={policyVariant === "default"}
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
                        aria-pressed={policyVariant === "with-s3"}
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
                        aria-expanded={showPolicyJson}
                        onClick={() => setShowPolicyJson((prev) => !prev)}
                        className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer bg-transparent border-none p-0"
                      >
                        {showPolicyJson ? "Hide JSON" : "View JSON"}
                      </button>
                      <button
                        type="button"
                        onClick={() => handleCopy("policy", activePolicyJson, "IAM policy JSON")}
                        className="text-[11px] text-slate-200 hover:text-white font-medium cursor-pointer bg-slate-800 border border-slate-700 px-2.5 py-1 rounded"
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
                  <p className="text-xs text-slate-300 pt-2.5 pl-4 leading-relaxed">
                    {item.answer}
                  </p>
                </details>
              ))}
            </div>
          </section>
        </main>

        {/* Minimal Footer */}
        <footer className="pt-4 border-t border-slate-800/70 flex flex-col items-center gap-2 text-xs text-slate-400">
          <div className="flex items-center gap-2 flex-wrap justify-center">
            <span>Built by</span>
            <a
              href="https://www.linkedin.com/in/david-danso/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-teal-400 transition-colors font-medium"
            >
              David Danso
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="https://github.com/DavidDanso/aws-clarity"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-teal-400 transition-colors font-medium"
            >
              Open Source (MIT)
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/AUDIT.md"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-teal-400 transition-colors font-medium"
            >
              Audit in 10 Minutes
            </a>
            <span aria-hidden="true">·</span>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-teal-400 hover:text-teal-300 transition-colors font-medium bg-transparent border-none p-0 cursor-pointer"
            >
              Trust &amp; Privacy Centre
            </button>
          </div>
          <p className="text-[11px] text-slate-500 text-center">
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
