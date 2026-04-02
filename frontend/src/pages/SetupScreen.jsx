import { useState } from "react";
import { validateRoleArn } from "../utils/formatters";
import { scanAccount, ERROR_MESSAGES } from "../services/api";

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

export default function SetupScreen({ onScanComplete }) {
  const [roleArn, setRoleArn] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(IAM_POLICY_JSON);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmit = async () => {
    setError("");

    if (!roleArn.trim()) {
      setError("Role ARN is required.");
      return;
    }

    if (!validateRoleArn(roleArn.trim())) {
      setError(
        "Invalid Role ARN format. Expected: arn:aws:iam::123456789012:role/RoleName"
      );
      return;
    }

    setLoading(true);
    try {
      const results = await scanAccount(roleArn.trim());
      console.log("Scan results:", results);
      onScanComplete(results);
    } catch (err) {
      setError(ERROR_MESSAGES[err.code] || err.message || "An unexpected error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white flex flex-col items-center justify-center px-4 py-12">
      {/* Header */}
      <div className="text-center mb-10">
        <div className="inline-flex items-center gap-2 mb-4">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
            <svg
              className="w-6 h-6 text-white"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">AWS Clarity</h1>
        </div>
        <p className="text-slate-400 text-lg max-w-md mx-auto">
          Scan your AWS account for resources, misconfigurations, and orphaned
          infrastructure in seconds.
        </p>
      </div>

      {/* Main Card */}
      <div className="w-full max-w-2xl bg-slate-800/60 border border-slate-700/50 rounded-2xl shadow-2xl backdrop-blur-sm p-8">
        {/* 3-Step IAM Guide */}
        <h2 className="text-xl font-semibold mb-6 text-slate-100">
          Setup Guide
        </h2>
        {/* Trust Banner */}
        <div className="flex items-start gap-3 bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 mb-8">
          <svg className="w-5 h-5 text-blue-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm text-blue-200/80 leading-relaxed">
            AWS Clarity never sees your AWS credentials. Instead, you create a read-only role inside your own account — we knock on that door temporarily to read your resources, then the access expires automatically. We cannot create, modify, or delete anything.
          </p>
        </div>

        <div className="space-y-6 mb-8">
          {/* Step 1 */}
          <div className="flex gap-4">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm font-bold border border-cyan-500/30">
              1
            </div>
            <div>
              <p className="font-medium text-slate-200">
                Create a read-only role in your AWS account
              </p>
              <p className="text-sm text-slate-400 mt-1.5 leading-relaxed">
                In your AWS Console, go to IAM → Roles → Create Role. When asked for the trust type, select 'Another AWS Account'. This tells AWS that AWS Clarity (which lives in a separate AWS account) is allowed to request temporary read access to your account. Enter this App Account ID:{" "}
                <code className="bg-slate-700/80 px-1.5 py-0.5 rounded text-cyan-300 text-xs font-medium">
                  {import.meta.env.VITE_APP_ACCOUNT_ID}
                </code>
                . Then set the External ID to{" "}
                <code className="bg-slate-700/80 px-1.5 py-0.5 rounded text-cyan-300 text-xs font-medium">
                  aws-clarity-scan
                </code>{" "}
                — this is a secret handshake that ensures only AWS Clarity can use this role, not anyone else who might know the account ID.
              </p>
            </div>
          </div>

          {/* Step 2 */}
          <div className="flex gap-4">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm font-bold border border-cyan-500/30">
              2
            </div>
            <div>
              <p className="font-medium text-slate-200">
                Attach the read-only permissions policy
              </p>
              <p className="text-sm text-slate-400 mt-1.5 leading-relaxed">
                Attach the policy below to your new role. Every permission in this list starts with Describe, List, or Get — none of them can create, change, or delete anything in your account. This is the minimum access needed to build your resource inventory.
              </p>
              <div className="mt-3 relative">
                <pre className="bg-slate-950/80 border border-slate-700/60 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto leading-relaxed">
                  {IAM_POLICY_JSON}
                </pre>
                <button
                  onClick={handleCopy}
                  className="absolute top-2 right-2 px-3 py-1 text-xs rounded-md bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors cursor-pointer shadow-sm"
                >
                  {copied ? "Copied!" : "Copy"}
                </button>
              </div>
            </div>
          </div>

          {/* Step 3 */}
          <div className="flex gap-4">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm font-bold border border-cyan-500/30">
              3
            </div>
            <div>
              <p className="font-medium text-slate-200">
                Copy your Role ARN and paste it below
              </p>
              <p className="text-sm text-slate-400 mt-1.5 leading-relaxed">
                After creating the role, AWS gives it a unique address called a Role ARN — it looks like{" "}
                <code className="bg-slate-700/80 px-1.5 py-0.5 rounded text-cyan-300 text-xs font-medium">
                  arn:aws:iam::123456789012:role/AWSClarityReadOnly
                </code>
                . This is not a password or credential. It is simply the address that tells AWS Clarity where your read-only door is. Paste it in the field below and click Scan.
              </p>
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-slate-700/50 my-6"></div>

        {/* ARN Input */}
        <div className="space-y-3">
          <label
            htmlFor="role-arn-input"
            className="block text-sm font-medium text-slate-300"
          >
            Role ARN
          </label>
          <input
            id="role-arn-input"
            type="text"
            value={roleArn}
            onChange={(e) => {
              setRoleArn(e.target.value);
              if (error) setError("");
            }}
            placeholder="arn:aws:iam::123456789012:role/AwsClarityReadOnly"
            className="w-full px-4 py-3 bg-slate-900/80 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-all text-sm"
            disabled={loading}
          />

          {/* Error Banner */}
          {error && (
            <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
              <svg
                className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5"
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
              <span>{error}</span>
            </div>
          )}

          {/* Submit Button */}
          <button
            id="scan-button"
            onClick={handleSubmit}
            disabled={loading}
            className="w-full py-3 rounded-xl font-semibold text-sm transition-all cursor-pointer
              bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500
              disabled:opacity-50 disabled:cursor-not-allowed
              shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <svg
                  className="animate-spin h-5 w-5 text-white"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Scanning...
              </span>
            ) : (
              "Scan My Account"
            )}
          </button>
        </div>
      </div>

      {/* Footer */}
      <p className="mt-8 text-xs text-slate-500">
        Read-only access only. No resources are modified.
      </p>
    </div>
  );
}
