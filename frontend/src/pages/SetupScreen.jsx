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
        "iam:GetRolePolicy"
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

        {/* Step content — built in Milestone 2 */}
        <div className="p-6">
          {currentStep === 1 && <div>{/* STEP 1 CONTENT */}</div>}
          {currentStep === 2 && <div>{/* STEP 2 CONTENT */}</div>}
          {currentStep === 3 && <div>{/* STEP 3 CONTENT */}</div>}
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

      <p className="text-xs text-gray-700 mt-4">Read-only access only. No resources are modified.</p>

    </div>
  );
}
