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

const RELEASE_VERSION = "1.1.0";
const RELEASE_WHEEL_FILE = `aws_clarity-${RELEASE_VERSION}-py3-none-any.whl`;
const RELEASE_TAG_URL = `https://github.com/DavidDanso/aws-clarity/releases/tag/v${RELEASE_VERSION}`;
const REPO_CLONE_URL = "https://github.com/DavidDanso/aws-clarity.git";

const INSTALL_PLATFORMS = [
  {
    id: "pipx",
    label: "pipx (Recommended)",
    requirement: "Requires Python 3.10+ and pipx. Installs aws-clarity in an isolated environment.",
    releaseWheelCmd: `pipx install ./${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npipx install .`,
    verifyCmd: "aws-clarity version",
    cliPrefix: "aws-clarity",
    checksumOs: "macOS / Linux",
  },
  {
    id: "unix",
    label: "macOS / Linux (venv)",
    requirement: "Requires Python 3.10+ built-in venv — no pipx needed.",
    releaseWheelCmd: `python3 -m venv ~/.aws-clarity\n~/.aws-clarity/bin/pip install ./${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npython3 -m venv ~/.aws-clarity\n~/.aws-clarity/bin/pip install .`,
    verifyCmd: "~/.aws-clarity/bin/aws-clarity version",
    cliPrefix: "~/.aws-clarity/bin/aws-clarity",
    checksumOs: "macOS / Linux",
  },
  {
    id: "windows",
    label: "Windows (PowerShell)",
    requirement: "Requires Python 3.10+ built-in venv in PowerShell.",
    releaseWheelCmd: `py -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .\\${RELEASE_WHEEL_FILE}`,
    sourceCmd: `git clone ${REPO_CLONE_URL}\ncd aws-clarity\npy -m venv "$HOME\\.aws-clarity"\n& "$HOME\\.aws-clarity\\Scripts\\pip.exe" install .`,
    verifyCmd: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe" version`,
    cliPrefix: `& "$HOME\\.aws-clarity\\Scripts\\aws-clarity.exe"`,
    checksumOs: "Windows (PowerShell)",
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
    note: `Compare the 64-character hex output against the ${RELEASE_WHEEL_FILE} entry in SHA256SUMS.txt.`,
  },
];

const SECURITY_PILLARS = [
  {
    title: "Local scanning",
    body: "The scanner runs on your computer and communicates directly with AWS using your configured local identity.",
  },
  {
    title: "Read-only assessment",
    body: "The CLI uses allowlisted read-only AWS API operations and does not intentionally create, update, or delete resources.",
  },
  {
    title: "No website credentials",
    body: "This website never asks for or requires AWS access keys, secret keys, or direct access to your AWS account.",
  },
  {
    title: "Local report review",
    body: "Imported JSON reports are parsed strictly in browser memory with Content-Security-Policy connect-src 'none' and zero uploads.",
  },
  {
    title: "Manual remediation",
    body: "AWS Clarity presents findings, evidence, and guidance. You review and perform any AWS changes yourself.",
  },
  {
    title: "Defined assessment scope",
    body: "Only supported checks and available configuration metadata are assessed. It does not imply complete AWS security coverage.",
  },
];

const FAQ_ITEMS = [
  {
    question: "Can I use AWS Clarity with a production AWS account?",
    answer:
      "AWS Clarity runs locally under the AWS credentials you select, calls only allowlisted read-only AWS APIs, and does not intentionally modify resources or upload reports to a backend. However, read-only configuration metadata can still be sensitive, supported rules do not cover every AWS service or risk, and the health score is not a security certification. Start with a non-production account or a dedicated read-only IAM role, and review the open-source code and IAM policy before running against production.",
  },
  {
    question: "Can the scanner modify my AWS resources?",
    answer:
      "No. The CLI enforces an allowlist of strictly read-only control-plane API operations (28 by default, plus 6 optional S3 metadata actions) and never performs automatic remediation. You still remain responsible for the permissions attached to the AWS identity you use.",
  },
  {
    question: "Will the scan cost money?",
    answer:
      "The default scan inspects 9 AWS services using 28 control-plane read APIs that carry $0 AWS API request charges. Optional S3 checks are off by default because AWS S3 bills LIST ($0.005/1,000) and GET ($0.0004/1,000) requests outside an account's 12-month S3 Free Tier; if you opt in with --include-s3-checks, the CLI displays pricing and asks for explicit confirmation first.",
  },
  {
    question: "Does the website receive my report?",
    answer:
      "No. Reports are parsed locally in browser memory, never uploaded to any server, and never automatically saved to localStorage or sessionStorage. Production builds enforce Content-Security-Policy connect-src 'none'. Closing or refreshing the tab clears the active report state.",
  },
  {
    question: "What AWS permissions are required?",
    answer:
      "The default scan requires 28 read-only Describe/List/Get actions across EC2, VPC, IAM, Lambda, RDS, DynamoDB, EBS, CloudWatch, and CloudTrail (plus 6 optional S3 bucket metadata actions if you opt into S3 checks). It never requests s3:ListBucket, s3:GetObject, or write permissions. Run aws-clarity policy --zero-cost-only or check docs/IAM_PERMISSIONS.md for the exact JSON.",
  },
  {
    question: "What information does the report contain?",
    answer:
      "The local JSON file contains allowlisted configuration metadata (such as security group ingress rules, IAM MFA and access key age, encryption flags, log retention, trail status, resource IDs/ARNs, and masked/full account identifiers) plus deterministic findings and coverage status. It never collects S3 file contents, database rows, Lambda code or environment variable values, tag values, log events, or AWS secrets.",
  },
];

const STEP_META = [
  {
    id: 1,
    shortLabel: "Install",
    title: "Install AWS Clarity",
    summary:
      "The scanner runs on your computer. It is the component that communicates with AWS and creates your assessment report.",
  },
  {
    id: 2,
    shortLabel: "Assess",
    title: "Assess your AWS account",
    summary:
      "Use your locally configured AWS identity to inspect the AWS services supported by AWS Clarity.",
  },
  {
    id: 3,
    shortLabel: "Review",
    title: "Review your assessment",
    summary:
      "Import the JSON report created by the scanner to explore your AWS assessment locally in your browser.",
  },
];

function DisclosurePanel({ title, subtitle = "", isOpen, onToggle, children }) {
  return (
    <div className="rounded-xl border border-slate-800/90 bg-slate-950/60">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left text-sm font-medium text-slate-200 hover:text-white transition-colors cursor-pointer bg-transparent border-0"
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
          className={`mt-0.5 shrink-0 text-teal-400 transition-transform ${isOpen ? "rotate-90" : ""}`}
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
        <span className="min-w-0">
          <span className="block">{title}</span>
          {subtitle && <span className="block text-sm font-normal text-slate-400 mt-0.5">{subtitle}</span>}
        </span>
      </button>
      {isOpen && (
        <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 text-sm text-slate-300 space-y-3 leading-relaxed">
          {children}
        </div>
      )}
    </div>
  );
}

function CommandBlock({ command, copyKey, copiedKey, onCopy, label }) {
  const isCopied = copiedKey === copyKey;
  return (
    <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-3.5 pr-24">
      <pre tabIndex={0} className="text-sm text-slate-100 font-mono overflow-x-auto leading-relaxed">
        {command}
      </pre>
      <button
        type="button"
        onClick={() => onCopy(copyKey, command, label)}
        className="absolute top-2.5 right-2.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 cursor-pointer transition-colors"
      >
        {isCopied ? "Copied ✓" : "Copy"}
      </button>
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
  const mainRef = useRef(null);
  const tabRefs = useRef([]);
  const stepsSectionRef = useRef(null);
  const stepRefs = useRef({});
  const howItWorksRef = useRef(null);
  const securitySectionRef = useRef(null);

  // Guided 3-step state: Step 1 expanded by default; Steps 2 & 3 collapsed
  const [activeStep, setActiveStep] = useState(1);
  const [confirmedSteps, setConfirmedSteps] = useState({ 1: false, 2: false });

  // Navigation & modal state
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);

  // Step 1 state
  const [installPlatform, setInstallPlatform] = useState("pipx");
  const [openPanels, setOpenPanels] = useState({});

  // Step 2 state
  const [includeS3, setIncludeS3] = useState(false);
  const [policyVariant, setPolicyVariant] = useState("default");
  const [showPolicyJson, setShowPolicyJson] = useState(false);

  // Step 3 state
  const [isDragging, setIsDragging] = useState(false);
  const [isParsingFile, setIsParsingFile] = useState(false);

  // Clipboard & screen reader live announcements
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

  const goToStep = (stepNumber, { markConfirmed = null, scroll = true } = {}) => {
    if (markConfirmed) {
      setConfirmedSteps((prev) => ({ ...prev, [markConfirmed]: true }));
    }
    setActiveStep(stepNumber);
    setStatusAnnouncement(`Opened Step ${stepNumber}: ${STEP_META[stepNumber - 1].title}.`);
    if (scroll) {
      requestAnimationFrame(() => {
        scrollToElement(stepRefs.current[stepNumber] || stepsSectionRef.current);
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
    <div className="min-h-[100dvh] bg-slate-950 text-slate-100 flex flex-col items-center px-4 sm:px-6 lg:px-8 pb-24">
      <button
        type="button"
        onClick={() => mainRef.current?.focus()}
        className="skip-link"
      >
        Skip to main content
      </button>

      {/* Polite live region for clipboard and step-change updates */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {statusAnnouncement}
      </div>

      {/* Hidden report file input shared by Step 3 and direct-import flows */}
      <input
        ref={fileInputRef}
        id="report-file-input"
        type="file"
        accept=".json,application/json"
        onChange={handleFileInputChange}
        className="hidden"
      />

      {/* A. Minimal Single-Row Header & Navigation */}
      <header className="w-full max-w-4xl py-5 sm:py-6 border-b border-slate-800/70">
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

          {/* Desktop inline navigation + mobile disclosure button (one <nav> landmark) */}
          <nav aria-label="Primary" className="flex items-center gap-1 sm:gap-5">
            <ul className="hidden sm:flex items-center gap-5 text-sm text-slate-300">
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
                  onClick={() => scrollToElement(securitySectionRef.current)}
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
                    className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/70 hover:border-slate-600 text-slate-200 hover:text-white text-sm font-medium transition-colors cursor-pointer"
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
              className="sm:hidden inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-800 bg-slate-900/70 text-sm font-medium text-slate-200 hover:text-white cursor-pointer"
            >
              <span>{mobileNavOpen ? "Close" : "Menu"}</span>
            </button>
          </nav>
        </div>

        {mobileNavOpen && (
          <ul
            id="mobile-primary-nav"
            className="sm:hidden mt-4 pt-3 border-t border-slate-800/80 flex flex-col gap-2 text-base text-slate-200"
          >
            <li>
              <button
                type="button"
                onClick={() => {
                  setMobileNavOpen(false);
                  scrollToElement(howItWorksRef.current);
                }}
                className="w-full text-left py-2 hover:text-white bg-transparent border-0 cursor-pointer"
              >
                How it works
              </button>
            </li>
            <li>
              <button
                type="button"
                onClick={() => {
                  setMobileNavOpen(false);
                  scrollToElement(securitySectionRef.current);
                }}
                className="w-full text-left py-2 hover:text-white bg-transparent border-0 cursor-pointer"
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
                className="block py-2 hover:text-white"
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
                className="block py-2 hover:text-white"
              >
                GitHub
              </a>
            </li>
            {onExploreDemo && (
              <li className="pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setMobileNavOpen(false);
                    onExploreDemo();
                  }}
                  className="w-full text-center py-2.5 px-4 rounded-xl border border-slate-700 bg-slate-900 text-slate-100 font-medium cursor-pointer"
                >
                  Explore Live Demo
                </button>
              </li>
            )}
          </ul>
        )}
      </header>

      <main
        ref={mainRef}
        id="main-content"
        tabIndex={-1}
        className="w-full max-w-4xl flex flex-col space-y-14 sm:space-y-20 pt-10 sm:pt-16 focus:outline-none"
      >
        {/* B. Hero Section */}
        <section aria-labelledby="hero-heading" className="space-y-6 sm:space-y-7">
          <div className="space-y-4">
            <h1
              id="hero-heading"
              className="clarity-hero-title font-bold text-white max-w-3xl"
            >
              Understand your AWS configuration. Know what needs attention.
            </h1>

            <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-[62ch]">
              AWS Clarity assesses supported AWS configuration using a read-only scanner that runs on
              your computer. Import the generated report to review findings, inspect evidence, and
              understand what to investigate.
            </p>
          </div>

          {/* Three restrained essential facts — clean single row on tablet/desktop */}
          <ul className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 sm:gap-4 max-w-3xl text-sm sm:text-[15px] text-slate-200">
            <li className="inline-flex items-center gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 rounded-full bg-teal-400 shrink-0" />
              <span>Scanner runs locally</span>
            </li>
            <li className="inline-flex items-center gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 rounded-full bg-teal-400 shrink-0" />
              <span>Read-only AWS operations</span>
            </li>
            <li className="inline-flex items-center gap-2.5">
              <span aria-hidden="true" className="w-2 h-2 rounded-full bg-teal-400 shrink-0" />
              <span>Reviewed locally in browser</span>
            </li>
          </ul>

          {/* Two clear entry paths */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-1">
            <button
              type="button"
              onClick={() => goToStep(1, { scroll: true })}
              className="w-full sm:w-auto min-h-[48px] px-6 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 active:bg-teal-300 text-slate-950 text-base font-bold transition-colors cursor-pointer"
            >
              Get started
            </button>
            <button
              type="button"
              onClick={() => goToStep(3, { scroll: true })}
              className="w-full sm:w-auto min-h-[48px] px-5 py-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-100 text-base font-semibold transition-colors cursor-pointer"
            >
              Already have a report? Import it
            </button>
          </div>

          {/* Resume active in-memory report when navigating back from dashboard */}
          {onResumeReport && (
            <div className="rounded-xl border border-teal-500/35 bg-teal-950/25 px-4 py-3.5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm">
              <span className="text-teal-100">
                Your report for{" "}
                <strong className="font-mono">Account {maskAccountId(resumableAccountId)}</strong>{" "}
                is still open in browser memory.
              </span>
              <button
                type="button"
                onClick={onResumeReport}
                className="text-sm font-semibold text-teal-300 hover:text-teal-200 underline underline-offset-2 cursor-pointer bg-transparent border-0 p-0 self-start sm:self-auto"
              >
                Return to Dashboard →
              </button>
            </div>
          )}
        </section>

        {/* C. Clean 3-Stage Workflow Explanation */}
        <section
          ref={howItWorksRef}
          id="how-it-works"
          aria-labelledby="workflow-heading"
          className="space-y-5"
        >
          <div className="space-y-1.5">
            <h2 id="workflow-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              How AWS Clarity works
            </h2>
            <p className="text-base text-slate-300 max-w-[65ch]">
              The website does not need direct access to your AWS account.
            </p>
          </div>

          <ol className="rounded-2xl border border-slate-800/90 bg-slate-900/35 divide-y md:divide-y-0 md:divide-x divide-slate-800/80 grid grid-cols-1 md:grid-cols-3">
            <li className="p-5 sm:p-6 space-y-2">
              <p className="text-sm font-semibold text-teal-300">
                Your computer → AWS account
              </p>
              <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                The CLI uses your selected local AWS identity to collect supported configuration
                information.
              </p>
            </li>
            <li className="p-5 sm:p-6 space-y-2">
              <p className="text-sm font-semibold text-teal-300">
                Your computer → JSON report
              </p>
              <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                The CLI evaluates deterministic rules locally and writes{" "}
                <code className="text-slate-100 whitespace-nowrap">aws-clarity-report.json</code>{" "}
                to your disk.
              </p>
            </li>
            <li className="p-5 sm:p-6 space-y-2">
              <p className="text-sm font-semibold text-teal-300">
                Your browser → AWS Clarity
              </p>
              <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed">
                You import the report here and review findings locally in browser memory.
              </p>
            </li>
          </ol>
        </section>

        {/* D. Guided Three-Step Experience (Step 1 open by default; Steps 2 & 3 collapsed) */}
        <section
          ref={stepsSectionRef}
          id="onboarding-steps"
          aria-labelledby="guided-steps-heading"
          className="space-y-6"
        >
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
            <div className="space-y-1">
              <h2 id="guided-steps-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Run your assessment in 3 steps
              </h2>
              <p className="text-sm sm:text-base text-slate-300">
                Follow one step at a time, or open any step directly.
              </p>
            </div>
            {activeStep !== 3 && (
              <button
                type="button"
                onClick={() => goToStep(3, { scroll: true })}
                className="self-start sm:self-auto text-sm font-medium text-teal-300 hover:text-teal-200 underline underline-offset-4 bg-transparent border-0 p-0 cursor-pointer"
              >
                Have a report already? Skip to Step 3 →
              </button>
            )}
          </div>

          {/* Calm linear step progress indicator (manual navigation — never pretends to verify local CLI state) */}
          <div aria-label="Assessment progress" className="grid grid-cols-3 gap-2.5">
            {STEP_META.map((step) => {
              const isCurrent = activeStep === step.id;
              const isConfirmed = Boolean(confirmedSteps[step.id]);
              return (
                <button
                  key={step.id}
                  type="button"
                  aria-current={isCurrent ? "step" : undefined}
                  onClick={() => goToStep(step.id, { scroll: false })}
                  className="group text-left space-y-2 bg-transparent border-0 p-0 cursor-pointer"
                >
                  <span
                    aria-hidden="true"
                    className={`block h-1.5 w-full rounded-full transition-colors ${
                      isCurrent
                        ? "bg-teal-400"
                        : isConfirmed
                        ? "bg-emerald-400/70"
                        : "bg-slate-800 group-hover:bg-slate-700"
                    }`}
                  />
                  <span
                    className={`block text-xs sm:text-sm font-medium transition-colors ${
                      isCurrent
                        ? "text-teal-300"
                        : isConfirmed
                        ? "text-emerald-300"
                        : "text-slate-400 group-hover:text-slate-200"
                    }`}
                  >
                    {step.id}. {step.shortLabel}
                    {isConfirmed && !isCurrent ? " ✓" : ""}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Guided Stepper Accordion (semantic <h3><button> headings per accessibility guidance) */}
          <div className="space-y-4">
            {/* ==================== STEP 1: INSTALL ==================== */}
            <div
              ref={(el) => {
                stepRefs.current[1] = el;
              }}
              id="step-1"
              className={`rounded-2xl border transition-colors ${
                activeStep === 1
                  ? "border-teal-500/45 bg-slate-900/70"
                  : "border-slate-800 bg-slate-900/35 hover:border-slate-700"
              }`}
            >
              <h3>
                <button
                  type="button"
                  id="step-1-trigger"
                  aria-expanded={activeStep === 1}
                  aria-controls="step-1-panel"
                  onClick={() => setActiveStep(activeStep === 1 ? 0 : 1)}
                  className="w-full flex items-start justify-between gap-4 p-5 sm:p-6 text-left cursor-pointer bg-transparent border-0"
                >
                  <div className="flex items-start gap-3.5 min-w-0">
                    <span
                      aria-hidden="true"
                      className={`w-8 h-8 rounded-full text-sm font-bold flex items-center justify-center shrink-0 mt-0.5 ${
                        activeStep === 1
                          ? "bg-teal-400 text-slate-950"
                          : confirmedSteps[1]
                          ? "bg-emerald-500/20 border border-emerald-500/40 text-emerald-300"
                          : "bg-slate-800 text-slate-200"
                      }`}
                    >
                      {confirmedSteps[1] && activeStep !== 1 ? "✓" : "1"}
                    </span>
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-base sm:text-lg font-semibold text-white">
                          Install AWS Clarity
                        </span>
                        {confirmedSteps[1] && (
                          <span className="text-xs font-medium text-emerald-300">
                            Confirmed by you
                          </span>
                        )}
                      </div>
                      <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[62ch]">
                        {STEP_META[0].summary}
                      </p>
                    </div>
                  </div>
                  <svg
                    aria-hidden="true"
                    xmlns="http://www.w3.org/2000/svg"
                    width="20"
                    height="20"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`mt-1 shrink-0 text-slate-400 transition-transform ${
                      activeStep === 1 ? "rotate-180 text-teal-300" : ""
                    }`}
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
              </h3>

              <div
                id="step-1-panel"
                hidden={activeStep !== 1}
                className="px-5 sm:px-6 pb-6 pt-2 border-t border-slate-800/80 space-y-5"
              >
                {/* Release & Python requirements */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm text-slate-300 bg-slate-950/60 border border-slate-800/80 rounded-xl px-4 py-3">
                  <div>
                    <span className="font-semibold text-white">
                      Published release: AWS Clarity CLI v{RELEASE_VERSION}
                    </span>
                    <span className="text-slate-400"> · Local scanner · Python 3.10+</span>
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

                {/* Single-platform selector so commands aren't dumped for every OS at once */}
                <div className="space-y-3">
                  <div
                    role="tablist"
                    aria-label="Choose your installation environment"
                    className="flex items-center gap-1 border-b border-slate-800 overflow-x-auto no-scrollbar"
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
                          {tab.label}
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
                        className="space-y-3"
                      >
                        <p className="text-sm text-slate-300">
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
                          command={tab.releaseWheelCmd}
                          copyKey={`wheel-${tab.id}`}
                          copiedKey={copiedKey}
                          onCopy={handleCopy}
                          label={`${tab.label} install command`}
                        />

                        <p className="text-sm text-slate-300">
                          Confirm installation locally by running{" "}
                          <code className="text-slate-100">{tab.verifyCmd}</code> — it should print{" "}
                          <code className="text-teal-300">
                            aws-clarity {RELEASE_VERSION} (local-first, read-only, zero telemetry)
                          </code>
                          .
                        </p>
                      </div>
                    );
                  })}
                </div>

                {/* Expandable optional sections inside Step 1 */}
                <div className="space-y-2.5">
                  <DisclosurePanel
                    title="Alternative installation: install from a source checkout"
                    subtitle="Use this if you want to inspect the repository locally before installing"
                    isOpen={Boolean(openPanels["alt-install"])}
                    onToggle={() => togglePanel("alt-install")}
                  >
                    <p>
                      Installing from a cloned Git checkout builds directly from source rather than
                      the pre-packaged <code className="text-slate-100">v{RELEASE_VERSION}</code>{" "}
                      release wheel. Avoid older <code className="text-slate-100">v1.0.0</code>,
                      which predates the read-only API allowlist, root-account block, and pre-scan
                      confirmation.
                    </p>
                    <CommandBlock
                      command={activePlatform.sourceCmd}
                      copyKey={`source-${activePlatform.id}`}
                      copiedKey={copiedKey}
                      onCopy={handleCopy}
                      label={`${activePlatform.label} source install command`}
                    />
                  </DisclosurePanel>

                  <DisclosurePanel
                    title="Verify Before Installing (SHA-256 checksums & build provenance)"
                    subtitle="Confirm download integrity against SHA256SUMS.txt or GitHub SLSA provenance"
                    isOpen={Boolean(openPanels["verify-release"])}
                    onToggle={() => togglePanel("verify-release")}
                  >
                    <p>
                      Published v{RELEASE_VERSION} release assets on{" "}
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
                      A SHA-256 checksum confirms download integrity against the release manifest —
                      it is <strong>not</strong> a cryptographic digital signature. You can also
                      verify GitHub Actions SLSA build provenance with{" "}
                      <code className="text-slate-100">
                        gh attestation verify {RELEASE_WHEEL_FILE} --repo DavidDanso/aws-clarity
                      </code>
                      .
                    </p>
                    <div className="space-y-2.5 pt-1">
                      {VERIFY_CHECKSUM_COMMANDS.map((item) => (
                        <div key={item.id} className="space-y-1.5">
                          <p className="text-xs font-semibold text-teal-300">{item.os}</p>
                          <CommandBlock
                            command={item.cmd}
                            copyKey={item.id}
                            copiedKey={copiedKey}
                            onCopy={handleCopy}
                            label={`${item.os} checksum command`}
                          />
                          <p className="text-xs text-slate-400">{item.note}</p>
                        </div>
                      ))}
                    </div>
                  </DisclosurePanel>
                </div>

                {/* Manual continuation action */}
                <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-t border-slate-800/70">
                  <p className="text-sm text-slate-400">
                    This website cannot detect whether the local CLI is installed.
                  </p>
                  <button
                    type="button"
                    onClick={() => goToStep(2, { markConfirmed: 1, scroll: true })}
                    className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm font-bold transition-colors cursor-pointer shrink-0"
                  >
                    I&apos;ve installed the CLI — Next: Assess →
                  </button>
                </div>
              </div>
            </div>

            {/* ==================== STEP 2: ASSESS ==================== */}
            <div
              ref={(el) => {
                stepRefs.current[2] = el;
              }}
              id="step-2"
              className={`rounded-2xl border transition-colors ${
                activeStep === 2
                  ? "border-teal-500/45 bg-slate-900/70"
                  : "border-slate-800 bg-slate-900/35 hover:border-slate-700"
              }`}
            >
              <h3>
                <button
                  type="button"
                  id="step-2-trigger"
                  aria-expanded={activeStep === 2}
                  aria-controls="step-2-panel"
                  onClick={() => setActiveStep(activeStep === 2 ? 0 : 2)}
                  className="w-full flex items-start justify-between gap-4 p-5 sm:p-6 text-left cursor-pointer bg-transparent border-0"
                >
                  <div className="flex items-start gap-3.5 min-w-0">
                    <span
                      aria-hidden="true"
                      className={`w-8 h-8 rounded-full text-sm font-bold flex items-center justify-center shrink-0 mt-0.5 ${
                        activeStep === 2
                          ? "bg-teal-400 text-slate-950"
                          : confirmedSteps[2]
                          ? "bg-emerald-500/20 border border-emerald-500/40 text-emerald-300"
                          : "bg-slate-800 text-slate-200"
                      }`}
                    >
                      {confirmedSteps[2] && activeStep !== 2 ? "✓" : "2"}
                    </span>
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-base sm:text-lg font-semibold text-white">
                          Assess your AWS account
                        </span>
                        {confirmedSteps[2] && (
                          <span className="text-xs font-medium text-emerald-300">
                            Confirmed by you
                          </span>
                        )}
                      </div>
                      <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[62ch]">
                        {STEP_META[1].summary}
                      </p>
                    </div>
                  </div>
                  <svg
                    aria-hidden="true"
                    xmlns="http://www.w3.org/2000/svg"
                    width="20"
                    height="20"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`mt-1 shrink-0 text-slate-400 transition-transform ${
                      activeStep === 2 ? "rotate-180 text-teal-300" : ""
                    }`}
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
              </h3>

              <div
                id="step-2-panel"
                hidden={activeStep !== 2}
                className="px-5 sm:px-6 pb-6 pt-2 border-t border-slate-800/80 space-y-6"
              >
                {/* Ordered 5-part assessment flow */}
                <ol className="space-y-5">
                  <li className="space-y-2">
                    <p className="text-base font-semibold text-white">
                      1. Select or sign in to your local AWS identity
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[65ch]">
                      AWS Clarity uses your existing AWS CLI or IAM Identity Center (SSO) profile
                      locally — this website never asks for AWS credentials.
                    </p>
                    <CommandBlock
                      command="aws sso login --profile your-readonly-profile"
                      copyKey="sso-login"
                      copiedKey={copiedKey}
                      onCopy={handleCopy}
                      label="AWS SSO login command"
                    />
                  </li>

                  <li className="space-y-2">
                    <p className="text-base font-semibold text-white">
                      2. Verify AWS identity and read-only permissions
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[65ch]">
                      Check your active account, enabled regions, and read permissions before
                      running a scan (add <code className="text-slate-100">--profile your-readonly-profile</code>{" "}
                      if you use a named profile).
                    </p>
                    <CommandBlock
                      command={doctorCommand}
                      copyKey="doctor-cmd"
                      copiedKey={copiedKey}
                      onCopy={handleCopy}
                      label="Doctor check command"
                    />
                  </li>

                  <li className="space-y-2">
                    <p className="text-base font-semibold text-white">
                      3. Run the local read-only assessment
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[65ch]">
                      By default, the scanner checks 9 supported AWS services using 28 read-only
                      control-plane APIs and skips S3 unless you explicitly opt in below.
                    </p>
                    <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-3.5 pr-24">
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
                        className="absolute top-2.5 right-2.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100 cursor-pointer transition-colors"
                      >
                        {copiedKey === "scan-cmd" ? "Copied ✓" : "Copy"}
                      </button>
                    </div>
                  </li>

                  <li className="space-y-1.5">
                    <p className="text-base font-semibold text-white">
                      4. Review the pre-scan confirmation
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[65ch]">
                      Before calling any service collector, the CLI prints your masked account ID,
                      caller ARN, credential source, target regions, service scope, and AWS fee
                      status so you can verify you are targeting the right account.
                    </p>
                  </li>

                  <li className="space-y-1.5">
                    <p className="text-base font-semibold text-white">
                      5. Confirm and generate your report
                    </p>
                    <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[65ch]">
                      Enter <code className="text-slate-100">y</code> to run the read-only scan.
                      The CLI writes <code className="text-slate-100">aws-clarity-report.json</code>{" "}
                      locally (owner-only mode <code className="text-slate-100">0600</code> on
                      macOS/Linux). Nothing in AWS is modified.
                    </p>
                  </li>
                </ol>

                {/* Concise, honest identity & read-only security callout */}
                <div className="rounded-xl border border-amber-500/30 bg-amber-950/15 px-4 py-4 space-y-2 text-sm">
                  <p className="font-semibold text-amber-200">
                    Recommended: use a dedicated read-only role first
                  </p>
                  <p className="text-slate-200 leading-relaxed max-w-[65ch]">
                    The CLI performs read-only AWS API operations and does not create, update, or
                    delete resources, and AWS account root credentials are refused by default.
                    However, you remain responsible for the permissions attached to your AWS
                    identity: an over-privileged credential is not made safe simply because the
                    scanner is read-only, a role is not safe simply because its name contains{" "}
                    <code className="text-slate-100">ReadOnly</code>, and AWS Clarity cannot prove
                    your identity&apos;s complete effective IAM permissions.
                  </p>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 pt-1 text-sm">
                    <a
                      href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/IAM_PERMISSIONS.md"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-2"
                    >
                      View least-privilege IAM policy
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
                      className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer"
                    >
                      Download default policy JSON
                    </button>
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

                {/* Deeper explanations on demand (5 clearly named expandable sections) */}
                <div className="space-y-2.5">
                  <DisclosurePanel
                    title="AWS authentication options"
                    subtitle="AWS SSO, named CLI profiles, environment variables, or local --role-arn"
                    isOpen={Boolean(openPanels["auth"])}
                    onToggle={() => togglePanel("auth")}
                  >
                    <p>
                      AWS Clarity uses the standard local <code className="text-slate-100">boto3</code>{" "}
                      credential chain. Pass <code className="text-slate-100">--profile name</code>{" "}
                      for a named AWS CLI or IAM Identity Center profile, or pass{" "}
                      <code className="text-slate-100">--role-arn arn:aws:iam::ACCOUNT:role/RoleName</code>{" "}
                      (with optional <code className="text-slate-100">--external-id</code>) to
                      assume a customer-owned read-only role locally.
                    </p>
                  </DisclosurePanel>

                  <DisclosurePanel
                    title="IAM permissions and least privilege (28 default / 34 with S3)"
                    subtitle="Inspect, copy, or download the exact read-only IAM policy JSON"
                    isOpen={Boolean(openPanels["iam"])}
                    onToggle={() => togglePanel("iam")}
                  >
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      {PERMISSION_PREVIEW_GROUPS.map((grp) => (
                        <div
                          key={grp.service}
                          className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 space-y-1"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-slate-100">{grp.service}</span>
                            <span className="text-xs font-mono text-slate-400">
                              {grp.actions.length} actions
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">{grp.summary}</p>
                        </div>
                      ))}
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          aria-pressed={policyVariant === "default"}
                          onClick={() => setPolicyVariant("default")}
                          className={`text-xs px-3 py-1.5 rounded-lg border cursor-pointer ${
                            policyVariant === "default"
                              ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                              : "bg-slate-900 border-slate-800 text-slate-300 hover:text-white"
                          }`}
                        >
                          28 Actions (Default)
                        </button>
                        <button
                          type="button"
                          aria-pressed={policyVariant === "with-s3"}
                          onClick={() => setPolicyVariant("with-s3")}
                          className={`text-xs px-3 py-1.5 rounded-lg border cursor-pointer ${
                            policyVariant === "with-s3"
                              ? "bg-teal-500/15 border-teal-500/40 text-teal-300 font-semibold"
                              : "bg-slate-900 border-slate-800 text-slate-300 hover:text-white"
                          }`}
                        >
                          34 Actions (With S3)
                        </button>
                      </div>

                      <div className="flex flex-wrap items-center gap-2.5">
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
                        className="text-xs text-slate-200 p-3.5 overflow-x-auto max-h-56 font-mono leading-relaxed bg-slate-950 rounded-lg border border-slate-800"
                      >
                        {activePolicyJson}
                      </pre>
                    )}
                  </DisclosurePanel>

                  <DisclosurePanel
                    title="Dedicated read-only role"
                    subtitle="Limit blast radius using a customer-owned role in your own AWS account"
                    isOpen={Boolean(openPanels["readonly-role"])}
                    onToggle={() => togglePanel("readonly-role")}
                  >
                    <p>
                      Deploy the open-source{" "}
                      <a
                        href="https://github.com/DavidDanso/aws-clarity/blob/main/infra/aws-clarity-readonly-role.yaml"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-teal-300 hover:text-teal-200 underline underline-offset-2"
                      >
                        CloudFormation read-only role template
                      </a>{" "}
                      in your own account, trusting only your own IAM user or SSO permission set
                      (never an external vendor account), then run{" "}
                      <code className="text-slate-100">
                        aws-clarity scan --role-arn &lt;RoleArn&gt; --output aws-clarity-report.json
                      </code>
                      .
                    </p>
                  </DisclosurePanel>

                  <DisclosurePanel
                    title="Optional S3 checks (off by default)"
                    subtitle="Explicit opt-in for S3 bucket configuration checks — may incur small AWS S3 API request fees"
                    isOpen={Boolean(openPanels["s3-optional"])}
                    onToggle={() => togglePanel("s3-optional")}
                  >
                    <p>
                      S3 checks are <strong>optional and skipped by default</strong> (marked{" "}
                      <code className="text-sky-300">SKIPPED_OPTIONAL</code>, never Healthy). When
                      enabled, the CLI inspects bucket policies, ACLs, Block Public Access, and
                      encryption settings using 6 bucket-metadata actions — it never lists or reads
                      objects (<code className="text-slate-100">s3:ListBucket</code> and{" "}
                      <code className="text-slate-100">s3:GetObject</code> are never called).
                    </p>
                    <p>
                      Because AWS S3 bills standard LIST ($0.005/1,000) and GET ($0.0004/1,000)
                      requests to your own AWS account outside the 12-month S3 Free Tier, the CLI
                      requires explicit consent when you pass{" "}
                      <code className="text-sky-300">--include-s3-checks</code>.
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
                        Add <code className="text-sky-300">--include-s3-checks</code> to the Step 2
                        commands above
                      </span>
                    </label>
                  </DisclosurePanel>

                  <DisclosurePanel
                    title="Scan confirmation, regions, and collected metadata"
                    subtitle="Scope regions with --regions, use --yes in scripts, and see what is never collected"
                    isOpen={Boolean(openPanels["regions-scope"])}
                    onToggle={() => togglePanel("regions-scope")}
                  >
                    <p>
                      By default, the CLI auto-discovers all enabled regions with a 90-second
                      collection time budget. For large accounts, scope specific regions with{" "}
                      <code className="text-slate-100">--regions us-east-1,eu-west-1</code> (and
                      pass <code className="text-slate-100">--yes</code> in non-interactive shells
                      after reviewing scope).
                    </p>
                    <p>
                      <strong className="text-white">Never collected:</strong> S3 object lists or
                      contents, RDS/DynamoDB rows, Lambda source code or environment variable
                      values, resource tag values, free-text descriptions, CloudWatch log events,
                      or AWS credentials.
                    </p>
                  </DisclosurePanel>
                </div>

                {/* Expected result & manual continuation */}
                <div className="rounded-xl bg-emerald-950/20 border border-emerald-500/25 px-4 py-3.5 text-sm text-emerald-100 leading-relaxed">
                  <strong className="text-emerald-300">Expected result after confirming the scan:</strong>{" "}
                  Your assessment report has been generated on your computer. You are ready to
                  review it.
                </div>

                <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-t border-slate-800/70">
                  <button
                    type="button"
                    onClick={() => goToStep(1, { scroll: true })}
                    className="self-start sm:self-auto text-sm font-medium text-slate-300 hover:text-white bg-transparent border-0 p-0 cursor-pointer"
                  >
                    ← Back to Step 1
                  </button>
                  <button
                    type="button"
                    onClick={() => goToStep(3, { markConfirmed: 2, scroll: true })}
                    className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm font-bold transition-colors cursor-pointer shrink-0"
                  >
                    I&apos;ve generated my report — Next: Review →
                  </button>
                </div>
              </div>
            </div>

            {/* ==================== STEP 3: IMPORT & REVIEW ==================== */}
            <div
              ref={(el) => {
                stepRefs.current[3] = el;
              }}
              id="step-3"
              className={`rounded-2xl border transition-colors ${
                activeStep === 3
                  ? "border-teal-500/45 bg-slate-900/70"
                  : "border-slate-800 bg-slate-900/35 hover:border-slate-700"
              }`}
            >
              <h3>
                <button
                  type="button"
                  id="step-3-trigger"
                  aria-expanded={activeStep === 3}
                  aria-controls="step-3-panel"
                  onClick={() => setActiveStep(activeStep === 3 ? 0 : 3)}
                  className="w-full flex items-start justify-between gap-4 p-5 sm:p-6 text-left cursor-pointer bg-transparent border-0"
                >
                  <div className="flex items-start gap-3.5 min-w-0">
                    <span
                      aria-hidden="true"
                      className={`w-8 h-8 rounded-full text-sm font-bold flex items-center justify-center shrink-0 mt-0.5 ${
                        activeStep === 3
                          ? "bg-teal-400 text-slate-950"
                          : "bg-slate-800 text-slate-200"
                      }`}
                    >
                      3
                    </span>
                    <div className="space-y-1 min-w-0">
                      <span className="block text-base sm:text-lg font-semibold text-white">
                        Review your assessment
                      </span>
                      <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[62ch]">
                        {STEP_META[2].summary}
                      </p>
                    </div>
                  </div>
                  <svg
                    aria-hidden="true"
                    xmlns="http://www.w3.org/2000/svg"
                    width="20"
                    height="20"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`mt-1 shrink-0 text-slate-400 transition-transform ${
                      activeStep === 3 ? "rotate-180 text-teal-300" : ""
                    }`}
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
              </h3>

              <div
                id="step-3-panel"
                hidden={activeStep !== 3}
                className="px-5 sm:px-6 pb-6 pt-2 border-t border-slate-800/80 space-y-6"
              >
                {/* Clean, inviting Drag-and-Drop / File Picker */}
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
                      : "border-slate-700 bg-slate-950/75 hover:border-teal-500/50"
                  }`}
                >
                  <div className="space-y-4 max-w-md mx-auto">
                    <div className="space-y-1.5">
                      <p className="text-base sm:text-lg font-semibold text-white">
                        {isParsingFile
                          ? "Validating report locally…"
                          : "Drop aws-clarity-report.json here"}
                      </p>
                      <p className="text-sm text-slate-300">
                        You can turn off your Wi-Fi before dropping your report file. It works the
                        same.
                      </p>
                    </div>

                    <button
                      type="button"
                      disabled={isParsingFile}
                      onClick={() => fileInputRef.current?.click()}
                      className="min-h-[46px] px-6 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 active:bg-teal-300 disabled:opacity-60 text-slate-950 text-sm sm:text-base font-bold cursor-pointer transition-colors"
                    >
                      {isParsingFile ? "Reading File…" : "Choose Local Report File"}
                    </button>

                    <p className="text-xs sm:text-sm text-slate-400">
                      Accepted format: <code className="text-slate-200">.json</code> · Max 25 MB ·
                      Processed strictly in browser memory · Rejects AWS credential files
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

                {/* What the user gets in the dashboard (verified features only) */}
                <div className="space-y-2.5">
                  <p className="text-sm font-semibold text-white">
                    What you can review once your report opens
                  </p>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm text-slate-300 leading-relaxed">
                    <li className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5">
                      <strong className="text-slate-100 block mb-0.5">
                        Findings &amp; supporting evidence
                      </strong>
                      Inspect prioritized findings with AWS configuration evidence. Not every
                      finding is a confirmed vulnerability — validate in your account context.
                    </li>
                    <li className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5">
                      <strong className="text-slate-100 block mb-0.5">
                        Coverage &amp; limitations
                      </strong>
                      Review succeeded, failed, and skipped checks. Health scores are withheld
                      whenever mandatory coverage is incomplete.
                    </li>
                    <li className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5">
                      <strong className="text-slate-100 block mb-0.5">
                        Manual remediation guidance
                      </strong>
                      Read impact notes and step-by-step manual fix instructions. AWS Clarity never
                      changes AWS resources automatically.
                    </li>
                    <li className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5">
                      <strong className="text-slate-100 block mb-0.5">
                        Local comparison &amp; exports
                      </strong>
                      Import a newer report later to compare changes locally, or export full /
                      best-effort sanitized JSON and CSV files.
                    </li>
                  </ul>
                </div>

                <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/70">
                  <button
                    type="button"
                    onClick={() => goToStep(2, { scroll: true })}
                    className="text-sm font-medium text-slate-300 hover:text-white bg-transparent border-0 p-0 cursor-pointer"
                  >
                    ← Back to Step 2
                  </button>
                  <p className="text-xs sm:text-sm text-slate-400">
                    Closing or refreshing this tab clears the active report from browser memory.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* E. Security and Trust Section */}
        <section
          ref={securitySectionRef}
          id="security-control"
          aria-labelledby="security-heading"
          className="space-y-6"
        >
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
            <div className="space-y-1.5 max-w-[65ch]">
              <h2 id="security-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Your AWS access stays under your control
              </h2>
              <p className="text-base text-slate-300 leading-relaxed">
                A clear boundary between your AWS account, your computer, and this browser
                interface.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-4 text-sm shrink-0">
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

          <div className="rounded-2xl border border-slate-800/90 bg-slate-800/80 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px overflow-hidden">
            {SECURITY_PILLARS.map((pillar) => (
              <div
                key={pillar.title}
                className="bg-slate-950/95 p-5 sm:p-6 space-y-2"
              >
                <h3 className="text-base font-semibold text-white">{pillar.title}</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{pillar.body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* F. Compact Expandable Supported Services & Technical Detail */}
        <section aria-labelledby="scope-section-heading" className="space-y-3">
          <h2 id="scope-section-heading" className="sr-only">
            Supported AWS services and technical scope
          </h2>

          <details className="clarity-disclosure rounded-2xl border border-slate-800 bg-slate-900/40 px-5 sm:px-6 py-4">
            <summary className="text-base font-semibold text-slate-100 hover:text-white transition-colors">
              <span>What does AWS Clarity assess?</span>
            </summary>

            <div className="pt-5 mt-4 border-t border-slate-800/80 space-y-5 text-sm">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <p className="font-semibold text-emerald-300">
                    Default assessment: 9 AWS services (28 free read-only APIs)
                  </p>
                  <p className="text-slate-300 leading-relaxed">
                    {SUPPORTED_SERVICES.filter((svc) => svc !== "S3").join(", ")} — covering 16
                    default resource types across enabled regions.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-sky-500/30 space-y-2">
                  <p className="font-semibold text-sky-300">
                    Optional assessment: S3 buckets (+6 metadata APIs, opt-in)
                  </p>
                  <p className="text-slate-300 leading-relaxed">
                    Skipped by default (<code className="text-sky-300">SKIPPED_OPTIONAL</code>).
                    Checks public policies, ACLs, Block Public Access, and encryption without
                    listing or reading objects.
                  </p>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 divide-y divide-slate-800/70 overflow-hidden text-sm">
                {SERVICE_COVERAGE_MATRIX.map((row) => (
                  <div
                    key={row.service}
                    className="p-3.5 grid grid-cols-1 sm:grid-cols-12 gap-1.5 sm:gap-3"
                  >
                    <div className="sm:col-span-3">
                      <span className="font-semibold text-teal-300">{row.service}</span>
                      <span className="block text-xs text-slate-400">{row.scope}</span>
                    </div>
                    <div className="sm:col-span-4 text-slate-200">{row.resources.join(", ")}</div>
                    <div className="sm:col-span-5 text-slate-300 leading-relaxed">{row.checks}</div>
                  </div>
                ))}
              </div>

              <p className="text-slate-300 leading-relaxed max-w-[65ch]">
                <strong className="text-white">Current limitations:</strong> Services outside these
                10 (such as EKS, ECS, KMS, Route 53, Secrets Manager, and Organizations) are not
                assessed, and AWS Clarity does not inspect data-plane contents or calculate AWS
                bills.
              </p>

              <div className="flex flex-wrap items-center gap-5 text-sm">
                <a
                  href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/SUPPORTED_SERVICES_AND_RULES.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
                >
                  Full supported services &amp; rules (43 checks) →
                </a>
                <a
                  href="https://github.com/DavidDanso/aws-clarity/blob/main/docs/IAM_PERMISSIONS.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-teal-300 hover:text-teal-200 font-medium underline underline-offset-4"
                >
                  Exact IAM permissions →
                </a>
              </div>
            </div>
          </details>
        </section>

        {/* G. Concise FAQ & Proportionate Security Assurance Disclosure */}
        <section aria-labelledby="faq-heading" className="space-y-4">
          <h2 id="faq-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Frequently asked questions
          </h2>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/35 divide-y divide-slate-800/80 overflow-hidden">
            {FAQ_ITEMS.map((item) => (
              <details key={item.question} className="clarity-disclosure px-5 sm:px-6 py-4">
                <summary className="text-sm sm:text-base font-medium text-slate-100 hover:text-white transition-colors">
                  <span>{item.question}</span>
                </summary>
                <p className="text-sm sm:text-[15px] text-slate-300 pt-3 pl-5 leading-relaxed max-w-[65ch]">
                  {item.answer}
                </p>
              </details>
            ))}
          </div>
        </section>

        {/* Single, proportionate Security Assurance and Limitations disclosure */}
        <section
          aria-labelledby="security-assurance-heading"
          className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 sm:p-6 space-y-2.5"
        >
          <h2 id="security-assurance-heading" className="text-base font-semibold text-white">
            Security Assurance and Limitations
          </h2>
          <p className="text-sm sm:text-[15px] text-slate-300 leading-relaxed max-w-[68ch]">
            AWS Clarity has undergone maintainer-led security hardening, automated testing, and
            release verification, but it has <strong>not</strong> undergone an independent
            third-party penetration test or received a formal security certification. It provides
            visibility into supported AWS configurations and does not guarantee account security,
            replace AWS security services, or substitute for an independent professional security
            assessment.
          </p>
        </section>
      </main>

      {/* Minimal Footer */}
      <footer className="w-full max-w-4xl mt-16 pt-6 border-t border-slate-800/70 flex flex-col sm:flex-row items-center justify-between gap-3 text-sm text-slate-400">
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

        <div className="flex items-center gap-4 flex-wrap justify-center">
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
      </footer>

      <TrustModal
        isOpen={trustModalOpen}
        onClose={() => setTrustModalOpen(false)}
        dataControls={dataControls}
      />
    </div>
  );
}
