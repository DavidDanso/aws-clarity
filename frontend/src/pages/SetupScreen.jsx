import { useState, useEffect } from "react";
import { validateRoleArn } from "../utils/formatters";
import { SUPPORTED_REGIONS } from "../utils/constants";

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
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "rds:DescribeDBInstances",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
 }`;

const FAQ_ITEMS = [
  {
    question: "Is this safe?",
    answer: "Yes. AWS Clarity uses a read-only IAM role with strict permissions. We cannot create, modify, or delete any resources in your account."
  },
  {
    question: "What regions?",
    answer: "We support 12 major AWS regions across North America, Europe, Asia Pacific, and South America."
  },
  {
    question: "Revoke access?",
    answer: "You can delete or modify the IAM role in your AWS Console at any time to instantly revoke access."
  }
];

export default function SetupScreen({ onScanStart, scanError, setScanError }) {
  const [roleArn, setRoleArn] = useState("");
  const [localError, setLocalError] = useState("");
  const [copied, setCopied] = useState(false);
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");
  const [currentStep, setCurrentStep] = useState(1);
  const [openFaq, setOpenFaq] = useState(null);

  useEffect(() => {
    setCurrentStep(1);
  }, []);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(IAM_POLICY_JSON);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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
    <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-start px-4 py-10">

      {/* Hero */}
      <div className="text-center mb-6">
        <div className="flex items-center justify-center gap-2 mb-3">
          <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="text-lg font-semibold text-white tracking-tight">AWS Clarity</span>
        </div>
        <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight mb-1">
          Full visibility into your AWS account
        </h1>
        <p className="text-xs text-gray-400 mb-3">
          Security misconfigs, orphaned resources, and active spend — in one scan.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-2">
          {["🔒 Read-only", "⏱ Expires in 1hr", "🚫 No credentials stored"].map(label => (
            <span key={label} className="text-xs text-gray-400 bg-gray-800 border border-gray-700 rounded-full px-3 py-1">
              {label}
            </span>
          ))}
        </div>
      </div>

      {/* Wizard card */}
      <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-2xl shadow-2xl overflow-hidden">

        {/* Stepper header */}
        <div className="px-6 pt-5 pb-4 border-b border-gray-800">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500 font-medium">Step {currentStep} of 3</span>
            <span className="text-xs text-teal-400 font-medium">
              {currentStep === 1 && "Create Role"}
              {currentStep === 2 && "Attach Policy"}
              {currentStep === 3 && "Scan Account"}
            </span>
          </div>
          {/* Progress bar */}
          <div className="flex items-center gap-1.5">
            {[1, 2, 3].map(step => (
              <div
                key={step}
                className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                  step <= currentStep ? "bg-teal-500" : "bg-gray-700"
                }`}
              />
            ))}
          </div>
        </div>

        {/* Step content */}
        <div className="p-6">
          {currentStep === 1 && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white mb-1">Create a read-only IAM role</h2>
                <p className="text-xs text-gray-400 leading-relaxed">
                  In the AWS IAM Console, create a new role. When prompted for trusted entity, choose{" "}
                  <span className="text-gray-200 font-medium">Another AWS Account</span>{" "}
                  and enter:
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2.5">
                  <span className="text-xs text-gray-400">App Account ID</span>
                  <code className="text-xs text-teal-400 font-mono break-all">
                    {import.meta.env.VITE_APP_ACCOUNT_ID}
                  </code>
                </div>
                <div className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2.5">
                  <span className="text-xs text-gray-400">External ID</span>
                  <code className="text-xs text-teal-400 font-mono">aws-clarity-scan</code>
                </div>
              </div>

              <p className="text-xs text-gray-500">
                The External ID ensures only AWS Clarity can use this role — not anyone else who knows the account ID.
              </p>

              <div className="flex items-center justify-between pt-2">
                <a
                  href="https://console.aws.amazon.com/iam/home#/roles"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300 transition-colors"
                >
                  Open IAM Console
                  <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
                    <polyline points="15 3 21 3 21 9" />
                    <line x1="10" y1="14" x2="21" y2="3" />
                  </svg>
                </a>
                <button
                  onClick={() => setCurrentStep(2)}
                  className="flex items-center gap-1.5 bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-colors cursor-pointer"
                >
                  Next: Attach Policy
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </button>
              </div>
            </div>
          )}

          {currentStep === 2 && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white mb-1">Attach the permissions policy</h2>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Add this inline policy to your new role. Every permission is read-only — none can create, modify, or delete anything.
                </p>
              </div>

              <div className="rounded-xl border border-gray-700 overflow-hidden">
                <div className="flex items-center justify-between px-3 py-2 bg-gray-800 border-b border-gray-700">
                  <span className="text-xs text-gray-400 font-mono font-medium">IAM Policy JSON</span>
                  <button
                    onClick={handleCopy}
                    className="text-xs font-medium transition-colors text-teal-400 hover:text-teal-300 cursor-pointer"
                  >
                    {copied ? "Copied ✓" : "Copy"}
                  </button>
                </div>
                <pre className="text-xs text-gray-300 p-3 overflow-x-auto overflow-y-auto max-h-52 font-mono leading-relaxed bg-gray-950">
                  {IAM_POLICY_JSON}
                </pre>
              </div>

              <div className="flex items-center justify-between pt-1">
                <button
                  onClick={() => setCurrentStep(1)}
                  className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors cursor-pointer"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="15 18 9 12 15 6" />
                  </svg>
                  Back
                </button>
                <button
                  onClick={() => setCurrentStep(3)}
                  className="flex items-center gap-1.5 bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-colors cursor-pointer"
                >
                  Next: Enter ARN
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </button>
              </div>
            </div>
          )}

          {currentStep === 3 && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white mb-1">Paste your Role ARN and scan</h2>
                <p className="text-xs text-gray-400">
                  Copy the Role ARN from the IAM role you just created and paste it below.
                </p>
              </div>

              <div className="space-y-2">
                <input
                  type="text"
                  value={roleArn}
                  onChange={(e) => {
                    setRoleArn(e.target.value);
                    if (localError) setLocalError("");
                    if (scanError) setScanError("");
                  }}
                  placeholder="arn:aws:iam::123456789012:role/AWSClarityReadOnly"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500/30 transition-colors font-mono"
                />

                {activeError && (
                  <div className="flex items-start gap-2 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-400 bg-red-900/20 border-red-800/40">
                    <svg
                      className="w-4 h-4 text-red-400 shrink-0 mt-0.5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <span>{activeError}</span>
                  </div>
                )}
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Region</p>
                <div className="grid grid-cols-2 gap-1 max-h-40 overflow-y-auto pr-1">
                  {SUPPORTED_REGIONS.map(region => (
                    <label
                      key={region.id}
                      className={`flex items-center gap-2 text-xs rounded-lg px-2.5 py-2 cursor-pointer select-none transition-colors ${
                        selectedRegion === region.id
                          ? "bg-teal-500/10 text-teal-400 border border-teal-500/30"
                          : "text-gray-400 hover:text-gray-200 border border-transparent"
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
                      {region.label}
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <button
                  onClick={() => setCurrentStep(2)}
                  className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors cursor-pointer"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="15 18 9 12 15 6" />
                  </svg>
                  Back
                </button>

                <button
                  onClick={handleSubmit}
                  className="flex items-center gap-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm font-semibold px-5 py-2 rounded-lg transition-colors shadow-lg shadow-teal-500/10 cursor-pointer"
                >
                  Scan My Account
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </button>
              </div>
            </div>
          )}
        </div>

      </div>

      {/* FAQ — outside the card, compact links */}
      <div className="w-full max-w-md mt-4 px-1">
        {FAQ_ITEMS.map((item, index) => (
          <div key={index} className="border-b border-gray-800 last:border-b-0">
            <button
              onClick={() => setOpenFaq(prev => prev === index ? null : index)}
              className="w-full flex items-center justify-between py-2.5 text-left cursor-pointer"
            >
              <span className="text-xs text-gray-500 hover:text-gray-300 transition-colors">{item.question}</span>
              <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={`shrink-0 text-gray-600 transition-transform ${openFaq === index ? "rotate-180" : ""}`}>
                <polyline points="6 9 12 15 18 9" />
              </svg>
            </button>
            {openFaq === index && (
              <p className="text-xs text-gray-600 pb-2.5 leading-relaxed">{item.answer}</p>
            )}
          </div>
        ))}
      </div>

      <footer className="w-full max-w-md mt-4 px-1">

        {/* Top row — builder credit and LinkedIn */}
        <div className="flex items-center justify-between py-3 border-t border-gray-800/60">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-gray-500">Built by</span>
            <a
              href="https://www.linkedin.com/in/david-danso/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-medium text-gray-300 hover:text-teal-400 transition-colors"
            >
              David Danso
            </a>
            <span className="text-gray-700">·</span>
            <span className="text-xs text-gray-600">AWS Cloud Engineer</span>
          </div>

          {/* LinkedIn icon link */}
          <a
            href="https://www.linkedin.com/in/david-danso/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-teal-400 transition-colors group"
            aria-label="Connect on LinkedIn"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="currentColor" className="shrink-0">
              <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
            </svg>
            <span className="text-xs group-hover:text-teal-400 transition-colors">LinkedIn</span>
          </a>
        </div>

        {/* Bottom row — legal/trust */}
        <p className="text-xs text-gray-700 pb-2 text-center">
          Read-only access only. No resources are modified.
        </p>

      </footer>

    </div>
  );
}
