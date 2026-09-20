import { useState } from "react";
import { validateRoleArn } from "../utils/formatters";
import { SUPPORTED_REGIONS } from "../utils/constants";
import { checkPermissions } from "../services/api";

const IAM_POLICY_JSON = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeNatGateways",
        "ec2:DescribeInternetGateways",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "lambda:ListFunctions",
        "elasticloadbalancing:DescribeLoadBalancers",
        "dynamodb:ListTables",
        "cloudwatch:DescribeAlarms",
        "autoscaling:DescribeAutoScalingGroups",
        "ecs:ListClusters",
        "eks:ListClusters",
        "elasticache:DescribeCacheClusters",
        "sqs:ListQueues",
        "sns:ListTopics",
        "secretsmanager:ListSecrets",
        "apigateway:GET",
        "cloudformation:DescribeStacks",
        "events:ListRules",
        "ecr:DescribeRepositories",
        "redshift:DescribeClusters"
      ],
      "Resource": "*"
    }
  ]
}`;

const FAQ_ITEMS = [
  {
    question: "Is AWS Clarity safe to connect?",
    answer: "Yes. AWS Clarity uses a strictly read-only IAM role temporarily assumed via AWS STS for 1 hour. It cannot create, modify, stop, or delete any resources in your AWS account."
  },
  {
    question: "Does AWS Clarity ask for my AWS passwords or access keys?",
    answer: "No. AWS Clarity never asks for, handles, or stores AWS root passwords, IAM user credentials, or secret access keys. Authentication is handled entirely through temporary STS credentials."
  },
  {
    question: "What permissions does AWS Clarity require?",
    answer: "Only read-only (Describe and List) permissions for supported services. We never ask for admin rights or write permissions, and we make zero AWS billing or Cost Explorer API requests."
  },
  {
    question: "What is the External ID and why is it used?",
    answer: "The External ID ('aws-clarity-scan') ensures only AWS Clarity can assume this cross-account role, preventing the 'confused deputy' security vulnerability per official AWS IAM architecture guidelines."
  },
  {
    question: "What happens if a permission is missing?",
    answer: "AWS Clarity performs a partial scan. It inspects only the services you permitted, marks the scan as partial, and explains exactly which service was skipped and what permission is required."
  },
  {
    question: "How do I revoke access?",
    answer: "You can delete or modify the IAM role in your AWS Console at any time to instantly revoke access."
  }
];

export default function SetupScreen({ onScanStart, scanError, setScanError }) {
  const [roleArn, setRoleArn] = useState("");
  const [localError, setLocalError] = useState("");
  const [copied, setCopied] = useState(false);
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");
  const [openFaq, setOpenFaq] = useState(null);
  const [showRoleGuide, setShowRoleGuide] = useState(false);

  // Permission pre-check states
  const [isPrechecking, setIsPrechecking] = useState(false);
  const [precheckResults, setPrecheckResults] = useState(null);
  const [precheckError, setPrecheckError] = useState(null);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(IAM_POLICY_JSON);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrecheck = async () => {
    setLocalError("");
    setScanError("");
    setPrecheckError(null);

    if (!roleArn.trim()) {
      setLocalError("Role ARN is required to test permissions.");
      return;
    }

    if (!validateRoleArn(roleArn.trim())) {
      setLocalError("Invalid Role ARN format. Expected: arn:aws:iam::123456789012:role/RoleName");
      return;
    }

    setIsPrechecking(true);
    try {
      const resp = await checkPermissions(roleArn.trim());
      setPrecheckResults(resp.permission_checks || {});
    } catch (err) {
      setPrecheckError(err.message || "Failed to test role permissions.");
    } finally {
      setIsPrechecking(false);
    }
  };

  const handleSubmit = async () => {
    setLocalError("");
    setScanError("");

    if (!roleArn.trim()) {
      setLocalError("Role ARN is required.");
      return;
    }

    if (!validateRoleArn(roleArn.trim())) {
      setLocalError(
        "Invalid Role ARN format. Expected: arn:aws:iam::123456789012:role/RoleName"
      );
      return;
    }

    if (!selectedRegion) {
      setLocalError("Please select a region to scan.");
      return;
    }

    const trimmedArn = roleArn.trim();
    onScanStart(trimmedArn, [selectedRegion]);
  };

  const activeError = localError || scanError;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-start px-4 py-8 sm:py-12 text-slate-100">

      {/* Main Container */}
      <div className="w-full max-w-lg flex flex-col space-y-8">

        {/* ── HEADER ──────────────────────────────────────────────────────── */}
        <header className="flex flex-col items-center text-center">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-7 h-7 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="text-base font-semibold text-white tracking-tight">AWS Clarity</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Connect Your AWS Account
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-sm">
            Read-only configuration inspection and security posture assessment.
          </p>
        </header>

        {/* ── 1. WHAT CLARITY NEEDS & WHY (Trust Principles) ─────────────── */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 space-y-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Trust & Read-Only Guarantees
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="flex items-start gap-2">
              <span className="text-teal-400 text-sm">✓</span>
              <div>
                <span className="font-medium text-slate-200">Temporary STS Access</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  Assumed via AWS STS for 1 hour. No AWS passwords or keys are ever requested.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 text-sm">✓</span>
              <div>
                <span className="font-medium text-slate-200">Strictly Read-Only</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  Zero write or delete permissions. Cannot create, modify, stop, or delete resources.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 text-sm">✓</span>
              <div>
                <span className="font-medium text-slate-200">Metadata Inspection</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  Inspects configuration across EC2, S3, RDS, IAM, and VPC. Never reads internal files or DB rows.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-teal-400 text-sm">✓</span>
              <div>
                <span className="font-medium text-slate-200">Confused Deputy Protection</span>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-0.5">
                  Secured with an External ID to ensure only AWS Clarity can assume this cross-account role.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* ── 2. ROLE ARN INPUT & SETUP ───────────────────────────────────── */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-5">
          
          {/* Collapsible IAM Role Setup Guide */}
          <div>
            <button
              type="button"
              onClick={() => setShowRoleGuide(prev => !prev)}
              className="flex items-center justify-between w-full text-xs font-medium text-slate-300 hover:text-white py-1 transition-colors cursor-pointer"
            >
              <span className="flex items-center gap-1.5">
                <span className="text-teal-400">ℹ</span>
                <span>Need to create the read-only role? View setup steps</span>
              </span>
              <span className="text-slate-500">{showRoleGuide ? "Hide ▲" : "Show ▼"}</span>
            </button>

            {showRoleGuide && (
              <div className="mt-3 pt-3 border-t border-slate-800 text-xs space-y-3">
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  1. In the AWS IAM Console, create a new role with trusted entity:{" "}
                  <strong className="text-slate-200">Another AWS Account</strong>.
                </p>
                <div className="space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                    <span className="text-slate-500">App Account ID:</span>
                    <span className="text-teal-400">{import.meta.env.VITE_APP_ACCOUNT_ID || "123456789012"}</span>
                  </div>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                    <span className="text-slate-500">External ID:</span>
                    <span className="text-teal-400">aws-clarity-scan</span>
                  </div>
                </div>
                <div className="pt-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] text-slate-400">2. Attach this read-only inline policy:</span>
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="text-[11px] text-teal-400 hover:text-teal-300 font-medium cursor-pointer"
                    >
                      {copied ? "Copied ✓" : "Copy Policy JSON"}
                    </button>
                  </div>
                  <pre className="text-[10px] text-slate-300 p-2.5 overflow-x-auto max-h-36 font-mono leading-relaxed bg-slate-950 rounded border border-slate-800">
                    {IAM_POLICY_JSON}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Role ARN input + Test Permissions */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label htmlFor="role-arn-input" className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Role ARN
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

            {/* Precheck error */}
            {precheckError && (
              <div className="flex items-start gap-2 border border-red-800/40 rounded-lg px-3 py-2 text-xs text-red-300 bg-red-950/30">
                <span className="text-red-400 font-bold shrink-0">⚠</span>
                <span>{precheckError}</span>
              </div>
            )}

            {/* Precheck results display */}
            {precheckResults && (
              <div className="mt-2 rounded-lg bg-slate-950 border border-slate-800 p-3 space-y-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Permission Pre-Check</span>
                  <span className="text-[10px] text-teal-400 font-mono">Read-Only</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {Object.entries(precheckResults).map(([svc, info]) => {
                    const isOk = info.status === "PASSED";
                    return (
                      <div key={svc} className="flex items-center gap-1.5 min-w-0">
                        <span className={isOk ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                          {isOk ? "✓" : "⚠"}
                        </span>
                        <span className="text-slate-300 font-medium truncate">{svc}</span>
                        <span className={`text-[10px] px-1 rounded truncate ${isOk ? "text-emerald-400/80 bg-emerald-500/10" : "text-amber-400/80 bg-amber-500/10"}`}>
                          {isOk ? "Ready" : "Missing"}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {Object.values(precheckResults).some(info => info.status !== "PASSED") && (
                  <div className="mt-2 pt-2 border-t border-slate-800 text-[11px] space-y-1">
                    {Object.values(precheckResults).filter(info => info.status !== "PASSED").map(info => (
                      <div key={info.service} className="text-amber-300">
                        <span className="font-semibold">⚠ {info.service}:</span> Requires <code className="text-[10px] text-amber-200 font-mono bg-amber-950/60 px-1 py-0.5 rounded">{info.required_permission}</code>
                        <p className="text-slate-400 text-[10px] mt-0.5">Affected capability: {info.capability}. Without this, the scan will be partial.</p>
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
          </div>

          {/* Region selection */}
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Region to Scan</p>
            <div className="grid grid-cols-2 gap-1 max-h-36 overflow-y-auto pr-1">
              {SUPPORTED_REGIONS.map(region => (
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

          {/* Scan action */}
          <div className="pt-2">
            <button
              onClick={handleSubmit}
              className="w-full flex items-center justify-center gap-2 bg-teal-600 hover:bg-teal-500 text-white text-sm font-semibold py-2.5 px-4 rounded-lg transition-colors shadow-lg shadow-teal-500/10 cursor-pointer"
            >
              <span>Scan My Account</span>
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          </div>

        </div>

        {/* ── FAQ ACCORDION ────────────────────────────────────────────────── */}
        <div className="px-1 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Frequently Asked Questions
          </p>
          {FAQ_ITEMS.map((item, index) => (
            <div key={index} className="border-b border-slate-800/80 last:border-b-0">
              <button
                onClick={() => setOpenFaq(prev => prev === index ? null : index)}
                className="w-full flex items-center justify-between py-2 text-left cursor-pointer"
              >
                <span className="text-xs text-slate-400 hover:text-slate-200 transition-colors font-medium">{item.question}</span>
                <span className="text-slate-500 text-xs ml-2">{openFaq === index ? "−" : "+"}</span>
              </button>
              {openFaq === index && (
                <p className="text-xs text-slate-500 pb-2.5 leading-relaxed">{item.answer}</p>
              )}
            </div>
          ))}
        </div>

        {/* ── FOOTER ──────────────────────────────────────────────────────── */}
        <footer className="pt-4 border-t border-slate-800/60 flex flex-col items-center gap-2 text-xs text-slate-500">
          <div className="flex items-center gap-2">
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
          </div>
          <p className="text-[11px] text-slate-600">
            Read-only configuration inspection. Zero customer resources modified. Zero billing calls.
          </p>
        </footer>

      </div>

    </div>
  );
}
