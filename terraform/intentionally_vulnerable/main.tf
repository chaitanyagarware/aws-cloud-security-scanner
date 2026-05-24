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

resource "aws_iam_user" "risky_devops" {
  name = "risky-devops-user"
}

resource "aws_iam_user_policy" "risky_admin_like" {
  name = "risky-admin-like-policy"
  user = aws_iam_user.risky_devops.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
