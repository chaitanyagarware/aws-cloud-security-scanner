terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_iam_role" "security_readonly_role" {
  name = "security-readonly-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_security_principal_arn
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "security_readonly_policy" {
  name        = "security-readonly-policy"
  description = "Read-only access for security log review and findings triage."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrail",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyRead"
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:ListDetectors",
          "guardduty:GetDetector"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_security_readonly" {
  role       = aws_iam_role.security_readonly_role.name
  policy_arn = aws_iam_policy.security_readonly_policy.arn
}
