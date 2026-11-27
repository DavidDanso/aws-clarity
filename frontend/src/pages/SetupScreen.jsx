import { useRef, useState } from "react";
import { maskAccountId } from "../utils/formatters";
import {
  DEFAULT_ZERO_COST_IAM_ACTIONS,
  IAM_POLICY_DEFAULT_JSON,
  IAM_POLICY_JSON,
  OPTIONAL_S3_IAM_ACTIONS,
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

const RELEASE_VERSION = "1.1.0";
const RELEASE_WHEEL_FILE = `aws_clarity-${RELEASE_VERSION}-py3-none-any.whl`;
const RELEASE_TAG_URL = `https://github.com/DavidDanso/aws-clarity/releases/tag/v${RELEASE_VERSION}`;
const REPO_CLONE_URL = "https://github.com/DavidDanso/aws-clarity.git";

const DEFAULT_SERVICES = SUPPORTED_SERVICES.filter((svc) => svc !== "S3");
const TOTAL_RESOURCE_TYPES = SERVICE_COVERAGE_MATRIX.reduce(
  (sum, row) => sum + row.resources.length,
  0
);

const INSTALL_PLATFORMS = [
  {
    id: "pipx",
    label: "pipx",
    fullLabel: "pipx (Recommended)",
    requirement: "Requires Python 3.10+ and pipx. Installs aws-clarity in an isolated environment.",
    releaseWheelCmd: `pipx install ./${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npipx install .`,
    verifyCmd: "aws-clarity version",
    cliPrefix: "aws-clarity",
  },
  {
    id: "unix",
    label: "macOS / Linux",
    fullLabel: "macOS / Linux (venv)",
    requirement: "Requires Python 3.10+ built-in venv — no pipx required.",
    releaseWheelCmd: `python3 -m venv ~/.aws-clarity\n~/.aws-clarity/bin/pip install ./${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npython3 -m venv ~/.aws-clarity\n~/.aws-clarity/bin/pip install .`,
    verifyCmd: "~/.aws-clarity/bin/aws-clarity version",
    cliPrefix: "~/.aws-clarity/bin/aws-clarity",
  },
  {
    id: "windows",
    label: "Windows",
    fullLabel: "Windows (PowerShell)",
    requirement: "Requires Python 3.10+ built-in venv in PowerShell.",
    releaseWheelCmd: `py -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .\\${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npy -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .`,
    verifyCmd: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe" version`,
    cliPrefix: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe"`,
  },
];

const VERIFY_CHECKSUM_COMMANDS = [
  {
    id: "checksum-macos",
    os: "macOS",
    cmd: "shasum -a 256 -c SHA256SUMS.txt",
    note: "Run in the download folder containing the wheel and SHA256SUMS.txt. Look for ': OK'.",
  },
  {
    id: "checksum-linux",
    os: "Linux",
    cmd: "sha256sum -c SHA256SUMS.txt",
    note: "Run in the download folder containing the wheel and SHA256SUMS.txt. Look for ': OK'.",
  },
  {
    id: "checksum-windows",
    os: "Windows (PowerShell)",
    cmd: `(Get-FileHash .\\${RELEASE_WHEEL_FILE} -Algorithm SHA256).Hash.ToLower()`,
    note: `Compare the 64-character hex digest against the ${RELEASE_WHEEL_FILE} entry in SHA256SUMS.txt.`,
  },
];

const STEPS = [
  {
    id: 1,
    num: "01",
    label: "Install",
    shortDesc: "Get the local scanner.",
    panelTitle: "Install the AWS Clarity scanner",
  },
  {
    id: 2,
    num: "02",
    label: "Scan",
    shortDesc: "Assess supported AWS config.",
    panelTitle: "Scan your AWS account",
  },
  {
    id: 3,
    num: "03",
    label: "Review",
    shortDesc: "Import your JSON report.",
    panelTitle: "Review your assessment",
  },
];

const SECURITY_GROUPS = [
  {
    title: "Local scanner",
    body: "The Python CLI runs on your computer and connects directly to official AWS service endpoints using your locally configured identity. This website never asks for AWS access keys or secret keys.",
  },
  {
    title: "Read-only AWS API operations",
    body: "The scanner enforces an allowlist of strictly read-only control-plane operations and does not intentionally create, update, or delete AWS resources. All remediation remains manual.",
  },
  {
    title: "Local browser report processing",
    body: "Imported JSON reports are validated and explored strictly in browser memory with Content-Security-Policy connect-src 'none', zero uploads, and no automatic localStorage or sessionStorage persistence.",
  },
];

const FAQ_ITEMS = [
  {
    question: "Can I use AWS Clarity with a production AWS account?",
    answer:
      "AWS Clarity runs locally under the AWS credentials you choose, calls only allowlisted read-only AWS APIs, and does not intentionally modify AWS resources or upload reports to a backend. However, read-only configuration metadata can still be sensitive, supported rules do not cover every AWS service or risk, and the health score is not a security certification. Use a dedicated read-only IAM role or IAM Identity Center permission set, and review the open-source code and IAM policy before running against production.",
  },
  {
    question: "Can the scanner modify my AWS resources?",
    answer:
      `No. The CLI enforces an explicit allowlist of strictly read-only control-plane API operations (${DEFAULT_ZERO_COST_IAM_ACTIONS.length} by default, plus ${OPTIONAL_S3_IAM_ACTIONS.length} optional S3 metadata actions) and never performs automatic remediation. You still remain responsible for the permissions attached to your AWS identity.`,
  },
  {
    question: "Will the scan cost money?",
    answer:
      `The default scan assesses ${DEFAULT_SERVICES.length} AWS services using ${DEFAULT_ZERO_COST_IAM_ACTIONS.length} control-plane read APIs that carry $0 AWS API request charges. Optional S3 checks are off by default because AWS S3 bills LIST ($0.005/1,000) and GET ($0.0004/1,000) requests outside an account's 12-month S3 Free Tier; if you opt in with --include-s3-checks, the CLI displays pricing and asks for explicit confirmation first.`,
  },
  {
    question: "Does the website receive my report?",
    answer:
      "No. Reports are parsed locally in browser memory, never uploaded to any server, and never automatically saved to localStorage or sessionStorage. Production builds enforce Content-Security-Policy connect-src 'none'. Closing or refreshing the tab clears the active report state.",
  },
  {
    question: "What AWS permissions are required?",
    answer:
      `The default scan requires ${DEFAULT_ZERO_COST_IAM_ACTIONS.length} read-only Describe/List/Get actions across ${DEFAULT_SERVICES.join(", ")} (plus ${OPTIONAL_S3_IAM_ACTIONS.length} optional S3 bucket metadata actions when opted in). It never requests s3:ListBucket, s3:GetObject, or write permissions. Run aws-clarity policy --zero-cost-only or view docs/IAM_PERMISSIONS.md for the exact JSON.`,
  },
  {
    question: "What information does the report contain?",
    answer:
      "The local JSON file contains allowlisted configuration metadata (such as security group ingress rules, IAM MFA and access key age, encryption flags, log retention, trail status, resource IDs/ARNs, and account identifiers) plus deterministic findings and coverage status. It never collects S3 file contents, database rows, Lambda source code or environment variable values, tag values, log events, or AWS secrets.",
  },
];

function InlineDisclosure({ title, subtitle = "", isOpen, onToggle, children }) {
  return (
    <div className="border-t border-slate-800/80 first:border-t-0">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={onToggle}
        className="w-full flex items-start gap-2.5 py-3.5 text-left text-sm sm:text-[15px] font-medium text-slate-200 hover:text-white transition-colors cursor-pointer bg-transparent border-0"
      >
        <svg
          aria-hidden="true"
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={`mt-1 shrink-0 text-teal-400 transition-transform ${isOpen ? "rotate-90" : ""}`}
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
        <span className="min-w-0">
          <span className="block">{title}</span>
          {subtitle && (
            <span className="block text-sm font-normal text-slate-400 mt-0.5">{subtitle}</span>
          )}
        </span>
      </button>
      {isOpen && (
        <div className="pb-4 pl-6 text-sm sm:text-[15px] text-slate-300 space-y-3 leading-relaxed">
          {children}
        </div>
      )}
    </div>
  );
}

function CommandBlock({ label = "", command, copyKey, copiedKey, onCopy, copyAriaLabel }) {
  const isCopied = copiedKey === copyKey;
  return (
    <div className="space-y-1.5">
      {label && (
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</p>
      )}
      <div className="relative rounded-xl bg-slate-950 border border-slate-800 px-4 py-3.5 pr-28">
        <pre
          tabIndex={0}
          className="text-sm text-slate-100 font-mono overflow-x-auto leading-relaxed"
        >
          {command}
        </pre>
        <button
          type="button"
          onClick={() => onCopy(copyKey, command, copyAriaLabel || label || "Command")}
          className="absolute top-2.5 right-2.5 min-h-[34px] text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 cursor-pointer transition-colors"
        >
          {isCopied ? "Copied ✓" : "Copy"}
        </button>
      </div>
    </div>
  );
}

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
  const chooseFileBtnRef = useRef(null);
  const mainRef = useRef(null);
  const tabRefs = useRef([]);
  const howItWorksRef = useRef(null);
  const workspaceRef = useRef(null);
  const securityRef = useRef(null);

  // Fresh visits always begin on Step 1; no persisted onboarding state
  const [activeStep, setActiveStep] = useState(1);

  // Navigation & Trust modal
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  // Step 1 & Step 2 controls (preserving exact existing state & behaviour)
  const [installPlatform, setInstallPlatform] = useState("pipx");
  const [openPanels, setOpenPanels] = useState({});
  const [includeS3, setIncludeS3] = useState(false);
  const [policyVariant, setPolicyVariant] = useState("default");
  const [showPolicyJson, setShowPolicyJson] = useState(false);

  // Step 3 drag-and-drop & loading state
  const [isDragging, setIsDragging] = useState(false);
  const [isParsingFile, setIsParsingFile] = useState(false);

  // Clipboard & screen reader live region
  const [copiedKey, setCopiedKey] = useState(null);
  const [statusAnnouncement, setStatusAnnouncement] = useState("");

  const activePlatform =
    INSTALL_PLATFORMS.find((p) => p.id === installPlatform) || INSTALL_PLATFORMS[0];
  const s3Flag = includeS3 ? " --include-s3-checks" : "";
  const doctorCommand = `${activePlatform.cliPrefix} doctor${s3Flag}`;
  const scanCommand = `${activePlatform.cliPrefix} scan${s3Flag} --output aws-clarity-report.json`;

  const activePolicyJson =
    policyVariant === "with-s3" ? IAM_POLICY_JSON : IAM_POLICY_DEFAULT_JSON;
  const activePolicyFilename =
    policyVariant === "with-s3"
      ? "aws-clarity-readonly-policy-with-s3.json"
      : "aws-clarity-readonly-policy-default.json";

  const togglePanel = (key) => {
    setOpenPanels((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const scrollToElement = (el) => {
    if (!el) return;
    const prefersReduced =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "start" });
  };

  const selectStep = (stepNumber, { scroll = false, focusImport = false } = {}) => {
    setActiveStep(stepNumber);
    const meta = STEPS[stepNumber - 1];
    setStatusAnnouncement(`Step ${meta.num}: ${meta.panelTitle}.`);
    if (scroll || focusImport) {
      requestAnimationFrame(() => {
        if (scroll) {
          scrollToElement(workspaceRef.current);
        }
        if (focusImport) {
          chooseFileBtnRef.current?.focus({ preventScroll: true });
        }
      });
    }
  };

  const handleCopy = async (key, text, label = "Command") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setStatusAnnouncement(`${label} copied to clipboard.`);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Clipboard unavailable in restricted browser context
    }
  };

  const handleTabKeyDown = (e, idx) => {
    let nextIdx = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % INSTALL_PLATFORMS.length;
    else if (e.key === "ArrowLeft")
      nextIdx = (idx - 1 + INSTALL_PLATFORMS.length) % INSTALL_PLATFORMS.length;
    else if (e.key === "Home") nextIdx = 0;
    else if (e.key === "End") nextIdx = INSTALL_PLATFORMS.length - 1;

    if (nextIdx !== null) {
      e.preventDefault();
      setInstallPlatform(INSTALL_PLATFORMS[nextIdx].id);
      tabRefs.current[nextIdx]?.focus();
    }
  };

  const processSelectedFile = async (file) => {
    if (!file) return;
    if (setImportError) setImportError("");
    setActiveStep(3);
    setIsParsingFile(true);
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
      setStatusAnnouncement("Report validated locally. Opening dashboard.");
      onImportReport(parsed, sanitizeImportedFileName(file.name));
    } catch (err) {
      if (setImportError) {
        setImportError(err.message || "Could not import the selected report file.");
      }
      setStatusAnnouncement("Report import failed. Review the validation error message.");
    } finally {
      setIsParsingFile(false);
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
    <div className="min-h-[100dvh] bg-slate-950 text-slate-100 pb-20">
      <button
        type="button"
        onClick={() => mainRef.current?.focus()}
        className="skip-link"
      >
        Skip to main content
      </button>

      {/* Polite screen-reader announcer */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {statusAnnouncement}
      </div>

      {/* Hidden local JSON report input (untouched importer pipeline) */}
      <input
        ref={fileInputRef}
        id="report-file-input"
        type="file"
        accept=".json,application/json"
        onChange={handleFileInputChange}
        className="hidden"
      />

      {/* A. Shared-Grid Minimal Header */}
      <header className="border-b border-slate-800/70">
        <div className="clarity-shell py-5">
          <div className="flex items-center justify-between gap-4">
            <div className="inline-flex items-center gap-2.5 text-base font-semibold text-white min-w-0">
              <span
                aria-hidden="true"
                className="w-8 h-8 rounded-lg bg-teal-500/15 border border-teal-500/30 flex items-center justify-center text-teal-400 shrink-0"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </span>
              <span className="truncate tracking-tight">AWS Clarity</span>
            </div>

            <nav aria-label="Primary" className="flex items-center">
              <ul className="hidden md:flex items-center gap-7 text-sm text-slate-300">
                <li>
                  <button
                    type="button"
                    onClick={() => scrollToElement(howItWorksRef.current)}
                    className="hover:text-white transition-colors cursor-pointer bg-transparent border-0 p-0"
                  >
                    How it works
                  </button>
                </li>
                <li>
                  <button
                    type="button"
                    onClick={() => scrollToElement(securityRef.current)}
                    className="hover:text-white transition-colors cursor-pointer bg-transparent border-0 p-0"
                  >
                    Security
                  </button>
                </li>
                <li>
                  <a
                    href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/GETTING_STARTED.md"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-white transition-colors"
                  >
                    Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://github.com/DavidDanso/aws-clarity"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-white transition-colors"
                  >
                    GitHub
                  </a>
                </li>
                {onExploreDemo && (
                  <li>
                    <button
                      type="button"
                      onClick={onExploreDemo}
                      className="px-3.5 py-2 rounded-lg border border-slate-700 bg-slate-900/70 hover:border-slate-600 text-slate-200 hover:text-white text-sm font-medium transition-colors cursor-pointer"
                    >
                      Live Demo
                    </button>
                  </li>
                )}
              </ul>

              <button
                type="button"
                aria-expanded={mobileNavOpen}
                aria-controls="mobile-primary-nav"
                onClick={() => setMobileNavOpen((prev) => !prev)}
                className="md:hidden inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-800 bg-slate-900/70 text-sm font-medium text-slate-200 hover:text-white cursor-pointer"
              >
                <span>{mobileNavOpen ? "Close" : "Menu"}</span>
              </button>
            </nav>
          </div>

          {mobileNavOpen && (
            <ul
              id="mobile-primary-nav"
              className="md:hidden mt-4 pt-3 border-t border-slate-800/80 flex flex-col gap-1.5 text-base text-slate-200"
            >
              <li>
                <button
                  type="button"
                  onClick={() => {
                    setMobileNavOpen(false);
                    scrollToElement(howItWorksRef.current);
                  }}
                  className="w-full text-left py-2.5 hover:text-white bg-transparent border-0 cursor-pointer"
                >
                  How it works
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => {
                    setMobileNavOpen(false);
                    scrollToElement(securityRef.current);
                  }}
                  className="w-full text-left py-2.5 hover:text-white bg-transparent border-0 cursor-pointer"
                >
                  Security
                </button>
              </li>
              <li>
                <a
                  href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/GETTING_STARTED.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setMobileNavOpen(false)}
                  className="block py-2.5 hover:text-white"
                >
                  Documentation
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/DavidDanso/aws-clarity"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setMobileNavOpen(false)}
                  className="block py-2.5 hover:text-white"
                >
                  GitHub
                </a>
              </li>
              {onExploreDemo && (
                <li className="pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setMobileNavOpen(false);
                      onExploreDemo();
                    }}
                    className="w-full text-center py-2.5 px-4 rounded-xl border border-slate-700 bg-slate-900 text-slate-100 font-medium cursor-pointer"
                  >
                    Live Demo
                  </button>
                </li>
              )}
            </ul>
          )}
        </div>
      </header>

      <main
        ref={mainRef}
        id="main-content"
        tabIndex={-1}
        className="clarity-shell focus:outline-none"
      >
        {/* B. Two-Column Hero with Integrated Data-Boundary Visual */}
        <section
          aria-labelledby="hero-heading"
          className="py-10 sm:py-14 lg:py-16 grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-8 xl:gap-12 items-center"
        >
          {/* Left Column (~58%): Direct Product Message & Two Clear Entry Paths */}
          <div className="lg:col-span-7 space-y-6">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-teal-300">
              Local-First AWS Configuration Assessment
            </p>

            <h1 id="hero-heading" className="clarity-hero-title font-bold text-white">
              Understand your AWS environment. Find what needs attention.
            </h1>

            <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-[58ch]">
              Run a read-only configuration assessment from your computer. Review the generated
              report in your browser, inspect evidence, and understand what needs investigation.
            </p>

            <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-1">
              <button
                type="button"
                onClick={() => selectStep(1, { scroll: true })}
                className="w-full sm:w-auto min-h-[48px] px-6 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 active:bg-teal-300 text-slate-950 text-base font-bold transition-colors cursor-pointer"
              >
                Start an assessment
              </button>
              <button
                type="button"
                onClick={() => selectStep(3, { scroll: true, focusImport: true })}
                className="w-full sm:w-auto min-h-[48px] px-5 py-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-100 text-base font-semibold transition-colors cursor-pointer"
              >
                I already have a report
              </button>
            </div>

            {onResumeReport && (
              <div className="rounded-xl border border-teal-500/35 bg-teal-950/25 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm max-w-xl">
                <span className="text-teal-100">
                  Report for{" "}
                  <strong className="font-mono">
                    Account {maskAccountId(resumableAccountId)}
                  </strong>{" "}
                  is open in browser memory.
                </span>
                <button
                  type="button"
                  onClick={onResumeReport}
                  className="text-sm font-semibold text-teal-300 hover:text-teal-200 underline underline-offset-4 cursor-pointer bg-transparent border-0 p-0 self-start sm:self-auto"
                >
                  Return to Dashboard →
                </button>
              </div>
            )}
          </div>

          {/* Right Column (~42%): Minimal Architectural Data-Boundary Diagram */}
          <div
            ref={howItWorksRef}
            id="how-it-works"
            aria-label="How your assessment works"
            className="lg:col-span-5 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 xl:p-6 space-y-4"
          >
            <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">
              How your assessment works
            </p>

            {/* AWS Account Boundary */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-white">Your AWS account</span>
                <span className="text-xs font-mono text-slate-400">Read-only APIs</span>
              </div>
              <p className="text-sm text-slate-300">
                Supported configuration metadata only. No resources modified.
              </p>
            </div>

            {/* Directional Boundary Connector */}
            <div className="flex items-center gap-3 px-2 text-xs text-teal-300 font-medium">
              <span aria-hidden="true" className="text-base leading-none">
                ↓
              </span>
              <span>Local CLI communicates with AWS directly from your computer</span>
            </div>

            {/* User Computer & Local Browser Boundary */}
            <div className="rounded-xl border border-teal-500/30 bg-teal-950/15 p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-white">Your computer</span>
                <span className="text-xs font-mono text-teal-300">Stays local</span>
              </div>

              <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-1.5 xl:gap-2 text-xs font-medium text-slate-100">
                <span className="inline-flex items-center justify-center px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/80 whitespace-nowrap">
                  Local CLI
                </span>
                <span className="flex flex-col sm:inline-flex sm:flex-row sm:items-center gap-1.5 xl:gap-2">
                  <span aria-hidden="true" className="text-teal-400 self-center">
                    <span className="sm:hidden">↓</span>
                    <span className="hidden sm:inline">→</span>
                  </span>
                  <span className="inline-flex items-center justify-center px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/80 whitespace-nowrap">
                    JSON report
                  </span>
                </span>
                <span className="flex flex-col sm:inline-flex sm:flex-row sm:items-center gap-1.5 xl:gap-2">
                  <span aria-hidden="true" className="text-teal-400 self-center">
                    <span className="sm:hidden">↓</span>
                    <span className="hidden sm:inline">→</span>
                  </span>
                  <span className="inline-flex items-center justify-center px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/80 whitespace-nowrap">
                    Browser review
                  </span>
                </span>
              </div>
            </div>

            <p className="pt-2 border-t border-slate-800/80 text-sm text-slate-300 font-medium">
              The website does not need direct access to your AWS account.
            </p>
          </div>
        </section>

        {/* C. Restrained Trust Summary Strip (No Cards) */}
        <section aria-label="Core architectural guarantees" className="border-y border-slate-800/80 py-4">
          <ul className="grid grid-cols-1 md:grid-cols-3 gap-3 md:gap-8 text-sm sm:text-[15px] text-slate-200">
            <li className="flex items-start gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 mt-[0.42rem] rounded-full bg-teal-400 shrink-0" />
              <span>Scanner runs locally</span>
            </li>
            <li className="flex items-start gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 mt-[0.42rem] rounded-full bg-teal-400 shrink-0" />
              <span>AWS access uses read-only API operations</span>
            </li>
            <li className="flex items-start gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 mt-[0.42rem] rounded-full bg-teal-400 shrink-0" />
              <span>Imported reports are processed in browser memory</span>
            </li>
          </ul>
        </section>

        {/* D. Unified Onboarding Workspace (One Step Navigation + One Active Panel) */}
        <section
          ref={workspaceRef}
          id="onboarding-workspace"
          aria-labelledby="workspace-heading"
          className="py-12 sm:py-16 space-y-6"
        >
          <div className="space-y-1.5">
            <h2
              id="workspace-heading"
              className="text-2xl sm:text-[2rem] font-bold text-white tracking-tight"
            >
              Run your AWS assessment
            </h2>
            <p className="text-base text-slate-300 max-w-[65ch]">
              Install the scanner, inspect supported AWS configuration, then review your report.
            </p>
          </div>

          {/* Primary Workspace Container */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 overflow-hidden lg:grid lg:grid-cols-[276px_minmax(0,1fr)]">
            {/* Step Navigation Rail (Horizontal 3-up on <lg; Top-Anchored Vertical Rail on lg+) */}
            <div
              aria-label="Assessment steps"
              className="grid grid-cols-3 lg:flex lg:flex-col lg:justify-start border-b lg:border-b-0 lg:border-r border-slate-800/90 bg-slate-950/50 divide-x lg:divide-x-0 lg:divide-y divide-slate-800/80"
            >
              {STEPS.map((step) => {
                const isActive = activeStep === step.id;
                return (
                  <button
                    key={step.id}
                    id={`step-${step.id}-trigger`}
                    type="button"
                    aria-current={isActive ? "step" : undefined}
                    aria-expanded={isActive}
                    aria-controls={`step-${step.id}-panel`}
                    onClick={() => selectStep(step.id)}
                    className={`clarity-step-btn text-left px-3.5 py-4 sm:px-5 sm:py-5 lg:px-6 lg:py-5 lg:last:border-b lg:last:border-slate-800/80 transition-colors cursor-pointer border-0 flex flex-col justify-center ${
                      isActive
                        ? "bg-slate-900/90 text-white"
                        : "bg-transparent text-slate-300 hover:bg-slate-900/45 hover:text-white"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`text-xs font-mono font-semibold ${
                          isActive ? "text-teal-300" : "text-slate-400"
                        }`}
                      >
                        {step.num}
                      </span>
                      {isActive && (
                        <span className="hidden lg:inline text-xs font-medium text-teal-300">
                          Current step
                        </span>
                      )}
                    </div>
                    <span className="mt-1 text-sm sm:text-base font-semibold text-white">
                      {step.label}
                    </span>
                    <span className="hidden sm:block mt-1 text-sm text-slate-400 leading-snug">
                      {step.shortDesc}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Single Active Step Panel */}
            <div className="p-5 sm:p-8 lg:p-10 min-w-0">
              {/* ==================== STEP 1: INSTALL ==================== */}
              <div
                id="step-1-panel"
                hidden={activeStep !== 1}
                className="space-y-6 max-w-[74ch]"
              >
                <div className="space-y-2">
                  <p className="text-xs font-mono font-semibold uppercase tracking-wider text-teal-300">
                    Step 01 — Local Scanner
                  </p>
                  <h3 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                    Install the AWS Clarity scanner
                  </h3>
                  <p className="text-base text-slate-300 leading-relaxed">
                    The scanner runs on your computer. It is the component that communicates with
                    AWS and creates your assessment report.
                  </p>
                </div>

                {/* Release Metadata & Download Link */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 py-3 border-y border-slate-800/80 text-sm text-slate-300">
                  <div>
                    <strong className="text-white">
                      Published release: AWS Clarity CLI v{RELEASE_VERSION}
                    </strong>
                    <span className="text-slate-400"> · Python 3.10+ required</span>
                  </div>
                  <a
                    href={RELEASE_TAG_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4 shrink-0"
                  >
                    Download v{RELEASE_VERSION} on GitHub →
                  </a>
                </div>

                {/* Platform Selector Tabs (preserves exact existing tablist & keyboard handling) */}
                <div className="space-y-4">
                  <div
                    role="tablist"
                    aria-label="Choose your installation method"
                    className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-slate-800"
                  >
                    {INSTALL_PLATFORMS.map((tab, idx) => {
                      const selected = installPlatform === tab.id;
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
                          onClick={() => setInstallPlatform(tab.id)}
                          onKeyDown={(e) => handleTabKeyDown(e, idx)}
                          className={`clarity-tab shrink-0 px-3.5 py-2.5 text-sm font-medium cursor-pointer bg-transparent border-0 transition-colors whitespace-nowrap ${
                            selected ? "text-teal-300" : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {tab.fullLabel}
                        </button>
                      );
                    })}
                  </div>

                  {INSTALL_PLATFORMS.map((tab) => {
                    const selected = installPlatform === tab.id;
                    return (
                      <div
                        key={tab.id}
                        id={`install-panel-${tab.id}`}
                        role="tabpanel"
                        aria-labelledby={`install-tab-${tab.id}`}
                        hidden={!selected}
                        className="space-y-4"
                      >
                        <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                          Download <code className="text-teal-300">{RELEASE_WHEEL_FILE}</code> from{" "}
                          <a
                            href={RELEASE_TAG_URL}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-teal-300 hover:text-teal-200 underline underline-offset-2"
                          >
                            GitHub Release v{RELEASE_VERSION}
                          </a>
                          , then install locally. {tab.requirement}
                        </p>

                        <CommandBlock
                          label="Install command"
                          command={tab.releaseWheelCmd}
                          copyKey={`wheel-${tab.id}`}
                          copiedKey={copiedKey}
                          onCopy={handleCopy}
                          copyAriaLabel={`${tab.fullLabel} install command`}
                        />

                        <p className="text-sm text-slate-300 leading-relaxed">
                          After installing, run{" "}
                          <code className="text-slate-100">{tab.verifyCmd}</code> in your terminal
                          — it prints{" "}
                          <code className="text-teal-300">
                            aws-clarity {RELEASE_VERSION} (local-first, read-only, zero telemetry)
                          </code>
                          .
                        </p>
                      </div>
                    );
                  })}
                </div>

                {/* Advanced Installation & Release Verification Disclosures */}
                <div className="border-y border-slate-800/80">
                  <InlineDisclosure
                    title="Verify Before Installing (SHA-256 checksums & build provenance)"
                    subtitle="Check download integrity against SHA256SUMS.txt or GitHub SLSA provenance"
                    isOpen={Boolean(openPanels["verify-release"])}
                    onToggle={() => togglePanel("verify-release")}
                  >
                    <p>
                      Published v{RELEASE_VERSION} assets on{" "}
                      <a
                        href={RELEASE_TAG_URL}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-teal-300 hover:text-teal-200 underline underline-offset-2"
                      >
                        GitHub Release v{RELEASE_VERSION}
                      </a>{" "}
                      include <code className="text-slate-100">{RELEASE_WHEEL_FILE}</code>,{" "}
                      <code className="text-slate-100">aws_clarity-{RELEASE_VERSION}.tar.gz</code>,{" "}
                      <code className="text-slate-100">
                        aws-clarity-local-{RELEASE_VERSION}.tar.gz
                      </code>
                      , and <code className="text-slate-100">SHA256SUMS.txt</code>.
                    </p>
                    <p>
                      A SHA-256 checksum verifies download integrity against the manifest — it is{" "}
                      <strong>not</strong> a cryptographic digital signature. You can also verify
                      GitHub Actions SLSA build provenance with{" "}
                      <code className="text-slate-100">
                        gh attestation verify {RELEASE_WHEEL_FILE} --repo DavidDanso/aws-clarity
                      </code>
                      .
                    </p>
                    <div className="space-y-3 pt-1">
                      {VERIFY_CHECKSUM_COMMANDS.map((item) => (
                        <div key={item.id} className="space-y-1">
                          <CommandBlock
                            label={item.os}
                            command={item.cmd}
                            copyKey={item.id}
                            copiedKey={copiedKey}
                            onCopy={handleCopy}
                            copyAriaLabel={`${item.os} checksum command`}
                          />
                          <p className="text-xs text-slate-400">{item.note}</p>
                        </div>
                      ))}
                    </div>
                  </InlineDisclosure>

                  <InlineDisclosure
                    title="Alternative: install from a source checkout"
                    subtitle="Builds locally from Git instead of installing the verified published wheel"
                    isOpen={Boolean(openPanels["alt-install"])}
                    onToggle={() => togglePanel("alt-install")}
                  >
                    <p>
                      Installing from a cloned checkout builds directly from repository source and
                      is distinct from installing the checksummed{" "}
                      <code className="text-slate-100">v{RELEASE_VERSION}</code> release wheel.
                      Avoid older <code className="text-slate-100">v1.0.0</code>, which predates
                      the read-only API allowlist, root-account block, and pre-scan confirmation.
                    </p>
                    <CommandBlock
                      label={`${activePlatform.fullLabel} source checkout`}
                      command={activePlatform.sourceCmd}
                      copyKey={`source-${activePlatform.id}`}
                      copiedKey={copiedKey}
                      onCopy={handleCopy}
                      copyAriaLabel={`${activePlatform.fullLabel} source install command`}
                    />
                  </InlineDisclosure>
                </div>

                {/* Manual Continuation Row */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pt-1">
                  <p className="text-sm text-slate-400">
                    Installation happens locally; this website cannot detect whether the CLI is
                    installed.
                  </p>
                  <button
                    type="button"
                    onClick={() => selectStep(2, { scroll: true })}
                    className="w-full sm:w-auto min-h-[44px] px-5 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm sm:text-base font-bold transition-colors cursor-pointer shrink-0"
                  >
                    Continue to AWS scan →
                  </button>
                </div>
              </div>

              {/* ==================== STEP 2: SCAN ==================== */}
              <div
                id="step-2-panel"
                hidden={activeStep !== 2}
                className="space-y-6 max-w-[74ch]"
              >
                <div className="space-y-2">
                  <p className="text-xs font-mono font-semibold uppercase tracking-wider text-teal-300">
                    Step 02 — Read-Only Local Scan
                  </p>
                  <h3 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                    Scan your AWS account
                  </h3>
                  <p className="text-base text-slate-300 leading-relaxed">
                    Use an AWS identity already configured on your computer to assess the services
                    supported by AWS Clarity.
                  </p>
                </div>

                {/* Clear 5-part Sequence */}
                <ol className="space-y-5">
                  <li className="space-y-1.5">
                    <p className="text-base font-semibold text-white">
                      1. Use a configured local AWS identity
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                      AWS Clarity uses the standard local AWS SDK credential chain — your existing
                      AWS CLI default profile, a named profile (
                      <code className="text-slate-100">--profile name</code>), or a local role
                      assumption (<code className="text-slate-100">--role-arn</code> with optional{" "}
                      <code className="text-slate-100">--external-id</code>). If your profile uses
                      AWS IAM Identity Center (SSO) and needs a fresh session, sign in first with{" "}
                      <code className="text-slate-100">
                        aws sso login --profile your-profile
                      </code>
                      .
                    </p>
                  </li>

                  <li className="space-y-2">
                    <p className="text-base font-semibold text-white">
                      2. Verify identity and read-only permissions
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                      Confirm your active account, enabled regions, and read permissions before
                      scanning (append <code className="text-slate-100">--profile name</code> if
                      using a named profile).
                    </p>
                    <CommandBlock
                      label="Permission check"
                      command={doctorCommand}
                      copyKey="doctor-cmd"
                      copiedKey={copiedKey}
                      onCopy={handleCopy}
                      copyAriaLabel="Doctor permission check command"
                    />
                  </li>

                  <li className="space-y-2">
                    <p className="text-base font-semibold text-white">
                      3. Run the assessment
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                      Assesses {DEFAULT_SERVICES.length} default AWS services using{" "}
                      {DEFAULT_ZERO_COST_IAM_ACTIONS.length} read-only control-plane APIs and skips
                      S3 unless you opt in below.
                    </p>
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Scan command
                      </p>
                      <div className="relative rounded-xl bg-slate-950 border border-slate-800 px-4 py-3.5 pr-28">
                        <pre
                          tabIndex={0}
                          className="text-sm text-slate-100 font-mono overflow-x-auto leading-relaxed"
                        >
                          <span>{activePlatform.cliPrefix} scan</span>
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
                          className="absolute top-2.5 right-2.5 min-h-[34px] text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 cursor-pointer transition-colors"
                        >
                          {copiedKey === "scan-cmd" ? "Copied ✓" : "Copy"}
                        </button>
                      </div>
                    </div>
                  </li>

                  <li className="space-y-1">
                    <p className="text-base font-semibold text-white">
                      4. Review the pre-scan confirmation
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                      Before calling any service collector, the CLI displays your masked account
                      ID, caller ARN, credential source, target regions, service scope, and AWS fee
                      information so you can verify or cancel.
                    </p>
                  </li>

                  <li className="space-y-1">
                    <p className="text-base font-semibold text-white">
                      5. Confirm and generate the JSON report
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                      Confirm <code className="text-slate-100">y</code> to run the assessment and
                      write <code className="text-slate-100">aws-clarity-report.json</code> on your
                      computer (mode <code className="text-slate-100">0600</code> on macOS/Linux).
                      Nothing in AWS is intentionally modified.
                    </p>
                  </li>
                </ol>

                {/* Prominent, Clean Left-Accented Least-Privilege Security Guidance */}
                <div className="border-l-2 border-amber-400/70 pl-4 py-1 space-y-2 text-sm sm:text-[15px]">
                  <p className="font-semibold text-amber-200">
                    Recommended: use a dedicated read-only role first
                  </p>
                  <p className="text-slate-200 leading-relaxed">
                    The scanner performs read-only AWS API operations. You remain responsible for
                    the permissions attached to your AWS identity. Use a dedicated least-privilege
                    identity wherever possible — root credentials are refused by default, a role
                    with <code className="text-slate-100">ReadOnly</code> in its name does not
                    establish its actual permissions, and AWS Clarity cannot prove your
                    identity&apos;s complete effective IAM permissions.
                  </p>
                  <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 pt-0.5 text-sm">
                    <a
                      href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/IAM_PERMISSIONS.md"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
                    >
                      View IAM policy
                    </a>
                    <button
                      type="button"
                      onClick={() =>
                        downloadLocalFile(
                          "aws-clarity-readonly-policy-default.json",
                          `${IAM_POLICY_DEFAULT_JSON}\n`,
                          "application/json;charset=utf-8;"
                        )
                      }
                      className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4 bg-transparent border-0 p-0 cursor-pointer"
                    >
                      Download default policy JSON
                    </button>
                    <a
                      href="https://github.com/DavidDanso/aws-clarity/blob/main/infra/aws-clarity-readonly-role.yaml"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
                    >
                      CloudFormation read-only role template
                    </a>
                  </div>
                </div>

                {/* Expandable Optional S3 & IAM Policy / Region Details */}
                <div className="border-y border-slate-800/80">
                  <InlineDisclosure
                    title="Optional S3 checks (off by default)"
                    subtitle="Expands scope to S3 bucket configuration; requires explicit consent and may incur S3 request fees"
                    isOpen={Boolean(openPanels["s3-optional"])}
                    onToggle={() => togglePanel("s3-optional")}
                  >
                    <p>
                      S3 checks are <strong>optional and off by default</strong> (marked{" "}
                      <code className="text-sky-300">SKIPPED_OPTIONAL</code>, never Healthy).
                      Enabling them adds {OPTIONAL_S3_IAM_ACTIONS.length} bucket-metadata actions
                      for public policies, ACLs, Block Public Access, and encryption —{" "}
                      <code className="text-slate-100">s3:ListBucket</code> and{" "}
                      <code className="text-slate-100">s3:GetObject</code> are never called.
                    </p>
                    <p>
                      Outside your AWS account&apos;s 12-month S3 Free Tier, AWS bills S3 LIST
                      ($0.005/1,000) and GET ($0.0004/1,000) requests. The CLI prompts for explicit
                      consent whenever <code className="text-sky-300">--include-s3-checks</code> is
                      passed (or pass{" "}
                      <code className="text-slate-100">--confirm-s3-request-costs</code> in
                      non-interactive scripts).
                    </p>
                    <label className="inline-flex items-start gap-2.5 pt-1 cursor-pointer text-slate-100 select-none">
                      <input
                        id="include-s3-checkbox"
                        type="checkbox"
                        checked={includeS3}
                        onChange={(e) => setIncludeS3(e.target.checked)}
                        className="mt-1 rounded border-slate-700 bg-slate-950 text-teal-500 focus:ring-teal-500 cursor-pointer shrink-0"
                      />
                      <span>
                        Include <code className="text-sky-300">--include-s3-checks</code> in the
                        Step 2 commands above
                      </span>
                    </label>
                  </InlineDisclosure>

                  <InlineDisclosure
                    title="Inspect IAM policy JSON, regions & non-interactive flags"
                    subtitle="View exact 28/34 read-only IAM actions, --regions scoping, and what is never collected"
                    isOpen={Boolean(openPanels["iam-details"])}
                    onToggle={() => togglePanel("iam-details")}
                  >
                    <p>
                      By default, the CLI discovers all enabled AWS regions with a 90-second
                      collection budget. Scope specific regions with{" "}
                      <code className="text-slate-100">--regions us-east-1,eu-west-1</code>, and
                      use <code className="text-slate-100">--yes</code> only in non-interactive
                      shells after reviewing scope.
                    </p>
                    <p>
                      <strong className="text-white">Deliberately never collected:</strong> S3
                      object lists or contents, RDS/DynamoDB rows, Lambda source code or
                      environment variable values, resource tag values, free-text descriptions,
                      CloudWatch log events, or AWS credentials.
                    </p>
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          aria-pressed={policyVariant === "default"}
                          onClick={() => setPolicyVariant("default")}
                          className={`text-xs px-3 py-1.5 rounded-lg border cursor-pointer ${
                            policyVariant === "default"
                              ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                              : "bg-slate-950 border-slate-800 text-slate-300 hover:text-white"
                          }`}
                        >
                          {DEFAULT_ZERO_COST_IAM_ACTIONS.length} Actions (Default)
                        </button>
                        <button
                          type="button"
                          aria-pressed={policyVariant === "with-s3"}
                          onClick={() => setPolicyVariant("with-s3")}
                          className={`text-xs px-3 py-1.5 rounded-lg border cursor-pointer ${
                            policyVariant === "with-s3"
                              ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                              : "bg-slate-950 border-slate-800 text-slate-300 hover:text-white"
                          }`}
                        >
                          {DEFAULT_ZERO_COST_IAM_ACTIONS.length + OPTIONAL_S3_IAM_ACTIONS.length}{" "}
                          Actions (With S3)
                        </button>
                      </div>
                      <div className="flex flex-wrap items-center gap-3">
                        <button
                          type="button"
                          aria-expanded={showPolicyJson}
                          onClick={() => setShowPolicyJson((prev) => !prev)}
                          className="text-xs text-teal-300 hover:text-teal-200 font-medium cursor-pointer bg-transparent border-0 p-0"
                        >
                          {showPolicyJson ? "Hide JSON" : "View JSON"}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopy("policy", activePolicyJson, "IAM policy JSON")}
                          className="text-xs text-slate-100 hover:text-white font-medium cursor-pointer bg-slate-800 border border-slate-700 px-3 py-1.5 rounded-lg"
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
                          className="text-xs text-teal-200 hover:text-white font-medium cursor-pointer bg-teal-500/15 border border-teal-500/35 px-3 py-1.5 rounded-lg"
                        >
                          Download JSON
                        </button>
                      </div>
                    </div>
                    {showPolicyJson && (
                      <pre
                        tabIndex={0}
                        className="text-xs text-slate-200 p-4 overflow-x-auto max-h-56 font-mono leading-relaxed bg-slate-950 rounded-xl border border-slate-800"
                      >
                        {activePolicyJson}
                      </pre>
                    )}
                  </InlineDisclosure>
                </div>

                {/* Step 2 Footer Navigation */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pt-1">
                  <button
                    type="button"
                    onClick={() => selectStep(1)}
                    className="self-start sm:self-auto text-sm font-medium text-slate-300 hover:text-white bg-transparent border-0 p-0 cursor-pointer"
                  >
                    ← Back to Install
                  </button>
                  <button
                    type="button"
                    onClick={() => selectStep(3, { focusImport: true })}
                    className="w-full sm:w-auto min-h-[44px] px-5 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm sm:text-base font-bold transition-colors cursor-pointer shrink-0"
                  >
                    Continue to Review →
                  </button>
                </div>
              </div>

              {/* ==================== STEP 3: REVIEW ==================== */}
              <div
                id="step-3-panel"
                hidden={activeStep !== 3}
                className="space-y-7 max-w-[74ch]"
              >
                <div className="space-y-2">
                  <p className="text-xs font-mono font-semibold uppercase tracking-wider text-teal-300">
                    Step 03 — Local Browser Review
                  </p>
                  <h3 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                    Review your assessment
                  </h3>
                  <p className="text-base text-slate-300 leading-relaxed">
                    Import the JSON report generated by your scanner to explore your results.
                  </p>
                </div>

                {/* Primary Dropzone */}
                <div
                  id="import-report"
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  className={`rounded-2xl border-2 border-dashed p-7 sm:p-10 text-center transition-colors ${
                    isDragging
                      ? "border-teal-400 bg-teal-950/30"
                      : "border-slate-700 bg-slate-950/80 hover:border-teal-500/50"
                  }`}
                >
                  <div className="space-y-4 max-w-md mx-auto">
                    <div className="space-y-1.5">
                      <p className="text-base sm:text-lg font-semibold text-white">
                        {isParsingFile
                          ? "Validating report locally…"
                          : "Drop aws-clarity-report.json here"}
                      </p>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        After this page loads, report import works completely offline. You can turn
                        off your Wi-Fi before dropping your report file. It works the same.
                      </p>
                    </div>

                    <button
                      ref={chooseFileBtnRef}
                      id="choose-report-btn"
                      type="button"
                      disabled={isParsingFile}
                      onClick={() => fileInputRef.current?.click()}
                      className="min-h-[48px] px-6 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 active:bg-teal-300 disabled:opacity-60 text-slate-950 text-base font-bold cursor-pointer transition-colors"
                    >
                      {isParsingFile ? "Reading File…" : "Choose Local Report File"}
                    </button>

                    <p className="text-sm text-slate-400">
                      Accepts <code className="text-slate-200">.json</code> · Max 25 MB · Processed
                      in browser memory · Rejects AWS credential files
                    </p>
                  </div>

                  {importError && (
                    <div
                      role="alert"
                      className="mt-5 flex items-start gap-2.5 border border-red-800/70 rounded-xl px-4 py-3 text-sm text-red-100 bg-red-950/50 text-left break-words leading-relaxed"
                    >
                      <span aria-hidden="true" className="text-red-400 font-bold shrink-0">
                        ⚠
                      </span>
                      <span className="min-w-0">{importError}</span>
                    </div>
                  )}
                </div>

                {/* Compact Borderless 2-Column Overview of Dashboard Capabilities */}
                <div className="space-y-3 pt-1">
                  <p className="text-sm font-semibold text-white">
                    What is available once your report opens
                  </p>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4 text-sm text-slate-300 leading-relaxed">
                    <li>
                      <strong className="text-slate-100 block">
                        Findings &amp; supporting evidence
                      </strong>
                      Prioritized observations with AWS configuration evidence. Validate findings in
                      your account&apos;s context.
                    </li>
                    <li>
                      <strong className="text-slate-100 block">Coverage &amp; limitations</strong>
                      See succeeded, failed, and skipped checks. Health scores are withheld if
                      mandatory coverage is incomplete.
                    </li>
                    <li>
                      <strong className="text-slate-100 block">Manual remediation guidance</strong>
                      Impact notes and manual steps to investigate. AWS Clarity never changes AWS
                      resources automatically.
                    </li>
                    <li>
                      <strong className="text-slate-100 block">Comparison &amp; report exports</strong>
                      Compare against a newer scan locally or export full and best-effort sanitized
                      JSON or CSV files.
                    </li>
                  </ul>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800/80">
                  <button
                    type="button"
                    onClick={() => selectStep(2)}
                    className="text-sm font-medium text-slate-300 hover:text-white bg-transparent border-0 p-0 cursor-pointer"
                  >
                    ← Back to Scan
                  </button>
                  <p className="text-sm text-slate-400">
                    Closing or refreshing this tab clears the active report from browser memory.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* E. Security Section (3 Clean Borderless Columns — No 6-Card Grid) */}
        <section
          ref={securityRef}
          id="security-control"
          aria-labelledby="security-heading"
          className="py-12 sm:py-16 border-t border-slate-800/80 space-y-8"
        >
          <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
            <div className="space-y-1.5 max-w-[65ch]">
              <h2
                id="security-heading"
                className="text-2xl sm:text-[1.875rem] font-bold text-white tracking-tight"
              >
                Your AWS access stays under your control
              </h2>
              <p className="text-base text-slate-300">
                Clear separation between your AWS account, the local CLI, and this browser viewer.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-6 text-sm shrink-0">
              <a
                href="https://github.com/DavidDanso/aws-clarity/blob/main/SECURITY.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
              >
                Security documentation
              </a>
              <button
                type="button"
                onClick={() => setTrustModalOpen(true)}
                className="text-slate-200 hover:text-white font-medium underline underline-offset-4 bg-transparent border-0 p-0 cursor-pointer"
              >
                Trust &amp; Privacy Centre
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 lg:gap-10">
            {SECURITY_GROUPS.map((group) => (
              <div key={group.title} className="space-y-2">
                <h3 className="text-base sm:text-lg font-semibold text-white">{group.title}</h3>
                <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                  {group.body}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* F. Assessment Coverage Section (Source-Driven, Clean Progressive Disclosure) */}
        <section
          aria-labelledby="coverage-heading"
          className="py-12 sm:py-16 border-t border-slate-800/80 space-y-6"
        >
          <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
            <div className="space-y-1.5 max-w-[65ch]">
              <h2
                id="coverage-heading"
                className="text-2xl sm:text-[1.875rem] font-bold text-white tracking-tight"
              >
                What does AWS Clarity assess?
              </h2>
              <p className="text-base text-slate-300 leading-relaxed">
                Defined assessment scope across {SUPPORTED_SERVICES.length} AWS services and{" "}
                {TOTAL_RESOURCE_TYPES} resource types. Services outside this list are not assessed.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-6 text-sm shrink-0">
              <a
                href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/SUPPORTED_SERVICES_AND_RULES.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
              >
                Supported services &amp; rules
              </a>
              <a
                href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/IAM_PERMISSIONS.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-200 hover:text-white font-medium underline underline-offset-4"
              >
                IAM permissions
              </a>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 lg:gap-12">
            <div className="space-y-2">
              <h3 className="text-base font-semibold text-emerald-300">
                Default assessment ({DEFAULT_SERVICES.length} services ·{" "}
                {DEFAULT_ZERO_COST_IAM_ACTIONS.length} free read-only APIs)
              </h3>
              <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                {DEFAULT_SERVICES.join(", ")}. Covers common exposure, encryption, logging, IAM
                hygiene, and unused-resource checks without incurring AWS API request fees.
              </p>
            </div>

            <div className="space-y-2">
              <h3 className="text-base font-semibold text-sky-300">
                Optional S3 assessment (+{OPTIONAL_S3_IAM_ACTIONS.length} metadata APIs, opt-in)
              </h3>
              <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                Skipped by default (<code className="text-sky-300">SKIPPED_OPTIONAL</code>). Checks
                public bucket policies, ACLs, Block Public Access, and encryption without listing
                or reading S3 objects. Services such as EKS, ECS, KMS, Route 53, and Secrets
                Manager are outside v1 scope.
              </p>
            </div>
          </div>

          <details className="clarity-disclosure border-t border-slate-800/80 pt-4">
            <summary className="text-sm sm:text-base font-medium text-slate-200 hover:text-white transition-colors">
              <span>Inspect detailed service matrix &amp; IAM permission groups</span>
            </summary>

            <div className="pt-5 space-y-6 text-sm">
              <div className="divide-y divide-slate-800/80 border-y border-slate-800/80">
                {SERVICE_COVERAGE_MATRIX.map((row) => (
                  <div
                    key={row.service}
                    className="py-3 grid grid-cols-1 md:grid-cols-12 gap-1.5 md:gap-4"
                  >
                    <div className="md:col-span-3">
                      <span className="font-semibold text-teal-300">{row.service}</span>
                      <span className="block text-xs text-slate-400">{row.scope}</span>
                    </div>
                    <div className="md:col-span-4 text-slate-200">{row.resources.join(", ")}</div>
                    <div className="md:col-span-5 text-slate-300 leading-relaxed">{row.checks}</div>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
                {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                  <div key={grp.service} className="space-y-1">
                    <p className="font-semibold text-slate-100">
                      {grp.service}{" "}
                      <span className="text-xs font-mono font-normal text-slate-400">
                        ({grp.actions.length} actions)
                      </span>
                    </p>
                    <p className="text-xs text-slate-300 leading-relaxed">{grp.summary}</p>
                  </div>
                ))}
              </div>
            </div>
          </details>
        </section>

        {/* G. Clean Typographic FAQ (No Outer Box) */}
        <section
          aria-labelledby="faq-heading"
          className="py-12 sm:py-16 border-t border-slate-800/80 space-y-6"
        >
          <h2
            id="faq-heading"
            className="text-2xl sm:text-[1.875rem] font-bold text-white tracking-tight"
          >
            Frequently asked questions
          </h2>

          <div className="divide-y divide-slate-800/80 border-y border-slate-800/80">
            {FAQ_ITEMS.map((item) => (
              <details key={item.question} className="clarity-disclosure py-4">
                <summary className="text-base font-medium text-slate-100 hover:text-white transition-colors">
                  <span>{item.question}</span>
                </summary>
                <p className="text-sm sm:text-[15px] text-slate-300 pt-3 pl-5 leading-relaxed max-w-[68ch]">
                  {item.answer}
                </p>
              </details>
            ))}
          </div>
        </section>

        {/* H. Restrained Security Assurance and Limitations (Left-Accented Note, Not a Card) */}
        <section
          aria-labelledby="security-assurance-heading"
          className="py-8 sm:py-10"
        >
          <div className="border-l-2 border-slate-700 pl-5 space-y-2 max-w-[74ch]">
            <h2 id="security-assurance-heading" className="text-base font-semibold text-slate-100">
              Security Assurance and Limitations
            </h2>
            <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
              AWS Clarity has undergone maintainer-led security hardening, automated testing, and
              release verification, but it has <strong>not</strong> undergone an independent
              third-party penetration test or received a formal security certification. It provides
              visibility into supported AWS configurations and does not guarantee account security,
              replace AWS security services, or substitute for an independent professional security
              assessment.
            </p>
          </div>
        </section>
      </main>

      {/* Shared-Grid Minimal Footer */}
      <footer className="border-t border-slate-800/70 mt-6">
        <div className="clarity-shell py-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-400">
          <div className="flex items-center gap-3 flex-wrap justify-center">
            <span>
              Built by{" "}
              <a
                href="https://www.linkedin.com/in/david-danso/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-200 hover:text-teal-300 transition-colors font-medium"
              >
                David Danso
              </a>
            </span>
            <span aria-hidden="true">·</span>
            <a
              href="https://github.com/DavidDanso/aws-clarity"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-teal-300 transition-colors font-medium"
            >
              MIT License
            </a>
          </div>

          <div className="flex items-center gap-5 flex-wrap justify-center">
            <a
              href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/AUDIT.md"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-white transition-colors"
            >
              Audit Guide
            </a>
            <a
              href="https://github.com/DavidDanso/aws-clarity/blob/main/SECURITY.md"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-white transition-colors"
            >
              Security
            </a>
            <button
              type="button"
              onClick={() => setTrustModalOpen(true)}
              className="text-teal-300 hover:text-teal-200 transition-colors font-medium bg-transparent border-0 p-0 cursor-pointer"
            >
              Trust &amp; Privacy Centre
            </button>
          </div>
        </div>
      </footer>

      <TrustModal
        isOpen={trustModalOpen}
        onClose={() => setTrustModalOpen(false)}
        dataControls={dataControls}
      />
    </div>
  );
}
