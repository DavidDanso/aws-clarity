data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.app_name}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_cross_account_sts" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/*"]
  }
}

resource "aws_iam_policy" "lambda_cross_account" {
  name        = "${var.app_name}-assume-roles"
  description = "Allow Lambda to assume scanning roles in user accounts"
  policy      = data.aws_iam_policy_document.lambda_cross_account_sts.json
}

resource "aws_iam_role_policy_attachment" "lambda_cross_account_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_cross_account.arn
}

resource "aws_iam_role" "clarity_read_only" {
  name = "AWSClarityReadOnly"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_exec.arn
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "aws-clarity-scan"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "clarity_read_only_policy" {
  name = "AWSClarityReadOnlyPolicy"
  role = aws_iam_role.clarity_read_only.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeAddresses",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNatGateways",
          "ec2:DescribeInternetGateways",
          "elasticloadbalancing:DescribeLoadBalancers",
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "lambda:ListFunctions",
          "iam:ListRoles",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "sts:GetCallerIdentity",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "elasticache:DescribeCacheClusters",
          "redshift:DescribeClusters"
        ]
        Resource = "*"
      }
    ]
  })
}
