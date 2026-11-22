import { IAM_POLICY_ACTIONS } from "./constants.js";

/**
 * Generates an inspectable, least-privilege AWS CloudFormation YAML template that
 * creates ONLY a single read-only IAM Role (zero chargeable AWS resources).
 *
 * Uses the exact same 35 IAM actions from IAM_POLICY_ACTIONS (matching infra/iam.tf 1:1).
 */
export function buildCloudFormationTemplate({ appAccountId, externalId }) {
  const safeAccountId = /^\d{12}$/.test(String(appAccountId || "").trim())
    ? String(appAccountId).trim()
    : "REPLACE_WITH_AWS_CLARITY_ACCOUNT_ID";
  const safeExternalId = String(externalId || "aws-clarity-scan")
    .trim()
    .replace(/"/g, "");

  const actionLines = IAM_POLICY_ACTIONS.map((action) => `                  - "${action}"`).join("\n");

  return `AWSTemplateFormatVersion: "2010-09-09"
Description: >
  AWS Clarity Read-Only Visibility Role. Creates ONLY a single least-privilege
  read-only IAM Role (35 Describe/List/Get actions across 10 AWS services)
  with ExternalId protection. Creates zero billable AWS resources.

Parameters:
  AWSClarityAccountId:
    Type: String
    Default: "${safeAccountId}"
    AllowedPattern: "^[0-9]{12}$"
    Description: The 12-digit AWS account ID hosting the AWS Clarity scanner.
  ExternalId:
    Type: String
    Default: "${safeExternalId}"
    MinLength: 2
    MaxLength: 128
    AllowedPattern: "^[A-Za-z0-9+=,.@:/_-]{2,128}$"
    Description: Unique External ID for sts:ExternalId confused-deputy protection (not a secret).
  RoleName:
    Type: String
    Default: "AWSClarityReadOnly"
    Description: Name for the read-only IAM role created in your AWS account.

Resources:
  AWSClarityReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Description: Strictly read-only IAM role for AWS Clarity (10 supported v1 services, zero write/delete/data-read permissions).
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::\${AWSClarityAccountId}:root"
            Action:
              - "sts:AssumeRole"
            Condition:
              StringEquals:
                "sts:ExternalId": !Ref ExternalId
      Policies:
        - PolicyName: AWSClarityReadOnlyPolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: AWSClarityReadOnlyMetadata
                Effect: Allow
                Action:
${actionLines}
                Resource: "*"

Outputs:
  RoleArn:
    Description: Paste this IAM Role ARN into AWS Clarity Step 3 to verify and scan your account.
    Value: !GetAtt AWSClarityReadOnlyRole.Arn
  ExternalIdUsed:
    Description: The External ID configured on this role's trust relationship.
    Value: !Ref ExternalId
`;
}

export function downloadCloudFormationTemplate({ appAccountId, externalId }) {
  const yaml = buildCloudFormationTemplate({ appAccountId, externalId });
  const blob = new Blob([yaml], { type: "text/yaml;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", "aws-clarity-readonly-role.yaml");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
